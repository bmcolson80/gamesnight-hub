/**
 * GamesNight — Hub server: shared login, game launcher, presence, invites
 */

import express        from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import http           from 'http';
import path           from 'path';
import cookieParser   from 'cookie-parser';
import bcrypt         from 'bcryptjs';
import jwt            from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import { initDB, createUser, getUserByEmail, getUserById, getAllUsers,
         createOTP, getValidOTP, consumeOTP, updateUserPassword, upsertUser,
         savePushSubscription, removePushSubscription, setPushEnabled,
         getPushSubscriptions, getUserPushStatus } from './db.js';
import { Resend } from 'resend';
import webpush from 'web-push';

const resend = process.env.RESEND_API_KEY
  ? new Resend(process.env.RESEND_API_KEY)
  : null;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT      = process.env.PORT || 4000;

process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT EXCEPTION]', err.stack || err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});

const JWT_SECRET           = process.env.JWT_SECRET || 'azul-secret-change-in-production';
const INTERNAL_SYNC_SECRET = process.env.INTERNAL_SYNC_SECRET || '';
const ADMIN_EMAIL          = (process.env.ADMIN_EMAIL || 'bmcolson80@gmail.com').toLowerCase();

// ── Web Push / VAPID ────────────────────────────────────────
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC_KEY  || '';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL   = process.env.VAPID_EMAIL || 'mailto:admin@gamesnight.app';

if (VAPID_PUBLIC && VAPID_PRIVATE) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC, VAPID_PRIVATE);
  console.log('🔔 Push notifications enabled');
} else {
  console.log('⚠️  Push notifications disabled (set VAPID_PUBLIC_KEY + VAPID_PRIVATE_KEY)');
}

async function sendPushToUser(userId, payload) {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE) return;
  const subs = getPushSubscriptions(userId);
  for (const sub of subs) {
    try {
      await webpush.sendNotification(
        { endpoint: sub.endpoint, keys: sub.keys },
        JSON.stringify(payload)
      );
    } catch (err) {
      if (err.statusCode === 410) {
        removePushSubscription(userId, sub.endpoint);
        console.log('[push] Removed expired subscription for user', userId);
      } else {
        console.error('[push] Send failed:', err.message);
      }
    }
  }
}

// Mints a short-lived first-party-shaped JWT for a specific user, reusing the
// shared JWT_SECRET, so a push notification can deep-link straight into a
// sibling game already logged in via its /sso handoff.
function mintUserJWT(user, expiresIn = '15m') {
  return jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn });
}

// ── Games catalog ───────────────────────────────────────────
const GAMES = [
  { id:'azul',    name:'Azul',    icon:'/icon-azul.png',    url: process.env.AZUL_URL    || '' },
  { id:'mahjong', name:'Mah Jong', icon:'/icon-mahjong.png', url: process.env.MAHJONG_URL || '' },
].filter(g => g.url);

// ── Account sync (replicate-on-write across sibling games) ──
// Called after a local register/password-change so every sibling game ends
// up with the same password hash. Best-effort: a game being unreachable
// must never affect the caller's own local account, which is already saved.
function requireInternalSecret(req, res, next) {
  if (!INTERNAL_SYNC_SECRET || req.headers['x-internal-secret'] !== INTERNAL_SYNC_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

async function pushAccountSyncTo(game, payload) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    await fetch(`${game.url}/api/internal/sync-account`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Internal-Secret': INTERNAL_SYNC_SECRET },
      body: JSON.stringify(payload),
      signal: controller.signal,
    }).finally(() => clearTimeout(timeout));
  } catch (err) {
    console.error(`[sync-account] Failed to push to ${game.id}:`, err.message);
  }
}

// Fans an account update out to every game except the one it came from.
function fanOutAccountSync({ email, name, passwordHash, sourceGameId }) {
  for (const game of GAMES) {
    if (game.id === sourceGameId) continue;
    pushAccountSyncTo(game, { email, name, passwordHash, sourceGameId: 'hub' });
  }
}

async function sendOTPEmail(email, code) {
  if (!resend) { console.log(`[DEV] OTP for ${email}: ${code}`); return; }
  try {
    await resend.emails.send({
      from:    'GamesNight <noreply@' + (process.env.EMAIL_DOMAIN || 'gamesnight.app') + '>',
      to:      email,
      subject: 'Your GamesNight verification code',
      html: `
        <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;background:#0d1030;color:#f2f2f8;border-radius:12px">
          <h1 style="letter-spacing:4px;margin:0 0 24px">GAMESNIGHT</h1>
          <p style="margin:0 0 16px">Your verification code is:</p>
          <div style="background:#1c2050;border:2px dashed #6f8cff;border-radius:8px;padding:20px;text-align:center;margin:0 0 24px">
            <span style="font-family:monospace;font-size:36px;font-weight:700;letter-spacing:12px;color:#6f8cff">${code}</span>
          </div>
          <p style="color:rgba(242,242,248,0.5);font-size:12px;margin:0">This code expires in 15 minutes. If you didn't request this, you can safely ignore it.</p>
        </div>
      `,
    });
  } catch (err) {
    console.error('Email send failed:', err.message);
  }
}

// ── Presence / invite state ─────────────────────────────────
// hubClients: Map<ws, { userId, name }>
const hubClients = new Map();

// Invites addressed to a user who isn't currently WS-connected to the hub
// (the common case — most of the time a player is off inside a game, not
// sitting on the hub dashboard). Delivered as a push notification right
// away, then replayed as a live toast the next time that user's hub tab
// connects (e.g. after tapping the notification).
// pendingInvites: Map<toUserId, { fromUserId, fromName, game, ts }>
const pendingInvites = new Map();
const PENDING_INVITE_TTL_MS = 10 * 60 * 1000;

// ── Express setup ───────────────────────────────────────────
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/health', (_, res) => res.json({ ok:true, online: hubClients.size }));

function requireAuth(req, res, next) {
  const token = req.cookies?.gamesnight_token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired session' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.email?.toLowerCase() !== ADMIN_EMAIL)
    return res.status(403).json({ error: 'Forbidden' });
  next();
}

function generateId() { return Math.random().toString(36).substr(2,9); }

// Mints a short-lived JWT the hub uses to call a sibling game's own
// requireAuth+requireAdmin-gated admin endpoints on the admin's behalf,
// reusing the JWT_SECRET already shared for /sso rather than a new mechanism.
function mintAdminJWT() {
  return jwt.sign({ id: 'gamesnight-hub-admin', email: ADMIN_EMAIL, name: 'GamesNight Hub' }, JWT_SECRET, { expiresIn: '1m' });
}

// Azul reads a Bearer token; Mah Jong only reads its `token` cookie —
// same auth-shape distinction the existing migration scripts already handle.
async function fetchGameAdminData(game) {
  const adminToken = mintAdminJWT();
  const authHeaders = game.id === 'mahjong'
    ? { Cookie: `token=${adminToken}` }
    : { Authorization: `Bearer ${adminToken}` };
  const overviewPath = game.id === 'mahjong' ? '/api/admin/stats' : '/api/admin/overview';
  try {
    const [overviewRes, usersRes] = await Promise.all([
      fetch(`${game.url}${overviewPath}`, { headers: authHeaders }),
      fetch(`${game.url}/api/admin/users`, { headers: authHeaders }),
    ]);
    const overview  = overviewRes.ok ? await overviewRes.json() : null;
    const usersData = usersRes.ok ? await usersRes.json() : null;
    const users     = usersData?.users ?? [];
    return { id: game.id, name: game.name, ok: overviewRes.ok, overview, users };
  } catch (err) {
    return { id: game.id, name: game.name, ok: false, error: err.message, overview: null, users: [] };
  }
}

function setSessionCookie(res, token) {
  res.cookie('gamesnight_token', token, { httpOnly:true, sameSite:'lax', maxAge:30*24*60*60*1000 });
}

// ── Auth routes ────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, name, password } = req.body;
  if (!email || !name || !password)
    return res.status(400).json({ error: 'Email, name and password required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (getUserByEmail(email))
    return res.status(409).json({ error: 'An account with that email already exists' });

  const id   = generateId();
  const hash = await bcrypt.hash(password, 10);
  createUser({ id, email, name, password: hash });
  fanOutAccountSync({ email, name, passwordHash: hash, sourceGameId: 'hub' });

  const token = jwt.sign({ id, email, name }, JWT_SECRET, { expiresIn: '30d' });
  setSessionCookie(res, token);
  res.json({ ok:true, user:{ id, email, name } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = getUserByEmail(email);
  if (!user) return res.status(401).json({ error: 'No account found with that email' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Incorrect password' });

  const token = jwt.sign({ id:user.id, email:user.email, name:user.name }, JWT_SECRET, { expiresIn:'30d' });
  setSessionCookie(res, token);
  res.json({ ok:true, user:{ id:user.id, email:user.email, name:user.name } });
});

app.post('/api/logout', (_, res) => {
  res.clearCookie('gamesnight_token');
  res.json({ ok:true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = getUserById(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    user: { id:user.id, email:user.email, name:user.name },
    isAdmin: user.email.toLowerCase() === ADMIN_EMAIL,
  });
});

app.get('/api/games', (_, res) => {
  res.json({ games: GAMES.map(g => ({ id:g.id, name:g.name, icon:g.icon, url:g.url })) });
});

// Every other registered hub account — the invite panel's player list.
// Separate from live WS presence (hubClients): a player is invitable any
// time, not only while they happen to have the hub tab open, since an
// invite now reaches them via push if they're off playing another game.
app.get('/api/users', requireAuth, (req, res) => {
  const users = getAllUsers()
    .filter(u => u.id !== req.user.id)
    .map(u => ({ id: u.id, name: u.name }));
  res.json({ users });
});

// Calls each sibling game's own requireAuth-gated /api/my-games on this
// user's behalf (short-lived per-user JWT, same shared-secret trust the SSO
// handoff and admin dashboard already use) and merges the results so the
// hub dashboard can show "your active games" across the whole collection.
app.get('/api/my-active-games', requireAuth, async (req, res) => {
  const user = getUserById(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const token = mintUserJWT(user, '1m');

  const perGame = await Promise.all(GAMES.map(async (game) => {
    const authHeaders = game.id === 'mahjong'
      ? { Cookie: `token=${token}` }
      : { Authorization: `Bearer ${token}` };
    try {
      const r = await fetch(`${game.url}/api/my-games`, { headers: authHeaders });
      if (!r.ok) return [];
      const data = await r.json();
      const games = Array.isArray(data) ? data : (data.games || []);
      return games.map(g => ({ ...g, gameId: game.id, gameName: game.name, gameIcon: game.icon }));
    } catch (err) {
      console.error(`[my-active-games] Failed to reach ${game.id}:`, err.message);
      return [];
    }
  }));

  res.json({ games: perGame.flat() });
});

// Mints a fresh SSO redirect for a given game. Kept server-side (rather
// than the client building the URL itself) so the JWT is only ever read
// from the authenticated session cookie, not floating in client JS state.
app.get('/api/games/:id/launch', requireAuth, (req, res) => {
  const game = GAMES.find(g => g.id === req.params.id);
  if (!game) return res.status(404).json({ error: 'Unknown game' });
  const token = req.cookies.gamesnight_token;
  res.json({ url: `${game.url}/sso?token=${encodeURIComponent(token)}` });
});

// Called by a sibling game right after it registers a user or changes a
// password locally, so the hub (and in turn every other sibling game) ends
// up with the same password. Internal-secret-gated, not a user session route.
app.post('/api/internal/sync-account', requireInternalSecret, (req, res) => {
  const { email, name, passwordHash, sourceGameId } = req.body || {};
  if (!email || !name || !passwordHash)
    return res.status(400).json({ error: 'email, name and passwordHash required' });
  upsertUser({ id: generateId(), email, name, password: passwordHash });
  fanOutAccountSync({ email, name, passwordHash, sourceGameId: sourceGameId || 'hub' });
  res.json({ ok: true });
});

// ── Push notification routes ───────────────────────────────
app.get('/api/push/vapid-key', (_, res) => {
  res.json({ publicKey: VAPID_PUBLIC || null });
});

app.post('/api/push/subscribe', requireAuth, (req, res) => {
  const { endpoint, keys } = req.body;
  if (!endpoint || !keys) return res.status(400).json({ error: 'endpoint and keys required' });
  savePushSubscription({ id: generateId(), userId: req.user.id, endpoint, keys });
  res.json({ ok: true });
});

app.post('/api/push/unsubscribe', requireAuth, (req, res) => {
  const { endpoint } = req.body;
  if (!endpoint) return res.status(400).json({ error: 'endpoint required' });
  removePushSubscription(req.user.id, endpoint);
  res.json({ ok: true });
});

app.post('/api/push/enabled', requireAuth, (req, res) => {
  const { enabled } = req.body;
  setPushEnabled(req.user.id, !!enabled);
  res.json({ ok: true });
});

app.get('/api/push/status', requireAuth, (req, res) => {
  const status = getUserPushStatus(req.user.id);
  res.json({ ...status, vapidAvailable: !!(VAPID_PUBLIC && VAPID_PRIVATE) });
});

// One-time (and safely re-runnable) reconciliation: pushes every account
// currently in the hub's own DB out to every sibling game, so accounts that
// existed before account-sync shipped converge on one password everywhere.
// Runs in-process (this same server, same in-memory DB) rather than as a
// separate script, so it can't race the live server's own sql.js saves.
app.post('/api/admin/backfill-account-sync', requireAuth, requireAdmin, (req, res) => {
  const users = getAllUsers();
  for (const u of users) {
    fanOutAccountSync({ email: u.email, name: u.name, passwordHash: u.password, sourceGameId: 'hub' });
  }
  res.json({ ok: true, count: users.length });
});

// ── Password reset routes ──────────────────────────────────
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email?.trim()) return res.status(400).json({ error: 'Email required' });

  const user = getUserByEmail(email);
  if (!user) return res.json({ ok: true }); // avoid user enumeration

  const code      = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Math.floor(Date.now() / 1000) + 15 * 60;
  createOTP({ id: generateId(), email: email.trim(), code, expiresAt });
  await sendOTPEmail(user.email, code);
  res.json({ ok: true });
});

app.post('/api/verify-otp', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Email and code required' });

  const otp = getValidOTP(email, code.trim());
  if (!otp) return res.status(400).json({ error: 'Invalid or expired code. Please try again.' });

  const resetToken = jwt.sign(
    { email: email.toLowerCase().trim(), otpId: otp.id, purpose: 'password-reset' },
    JWT_SECRET,
    { expiresIn: '10m' }
  );
  res.json({ ok: true, resetToken });
});

app.post('/api/reset-password', async (req, res) => {
  const { resetToken, newPassword } = req.body;
  if (!resetToken || !newPassword) return res.status(400).json({ error: 'Token and new password required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  let payload;
  try {
    payload = jwt.verify(resetToken, JWT_SECRET);
  } catch {
    return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
  }
  if (payload.purpose !== 'password-reset') return res.status(400).json({ error: 'Invalid token' });

  consumeOTP(payload.otpId);
  const hash = await bcrypt.hash(newPassword, 10);
  updateUserPassword(payload.email, hash);

  const user = getUserByEmail(payload.email);
  fanOutAccountSync({ email: user.email, name: user.name, passwordHash: hash, sourceGameId: 'hub' });

  const token = jwt.sign({ id:user.id, email:user.email, name:user.name }, JWT_SECRET, { expiresIn:'30d' });
  setSessionCookie(res, token);
  res.json({ ok:true, user:{ id:user.id, email:user.email, name:user.name } });
});

// ── Admin routes ────────────────────────────────────────────
// The HTML shell has no sensitive data — access control happens at the
// /api/admin/* endpoint below, called client-side.
app.get('/admin', (_, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Consolidated analytics — calls each sibling game's own existing
// requireAuth+requireAdmin-gated admin endpoints and merges the results,
// so per-game dashboards can be retired in favor of this one view.
app.get('/api/admin/overview', requireAuth, requireAdmin, async (req, res) => {
  const perGame = await Promise.all(GAMES.map(fetchGameAdminData));
  const combined = perGame.reduce((acc, g) => {
    acc.totalUsers += g.users.length;
    acc.totalGamesStarted += g.overview?.totalGamesStarted ?? g.overview?.totalGames ?? 0;
    acc.activeGames += g.overview?.activeGames ?? 0;
    return acc;
  }, { totalUsers: 0, totalGamesStarted: 0, activeGames: 0, hubUsers: getAllUsers().length });
  res.json({ games: perGame, combined });
});

// ── HTTP/WS server ─────────────────────────────────────────
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  let identity = null;
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/gamesnight_token=([^;]+)/);
  if (match) {
    try {
      const payload = jwt.verify(match[1], JWT_SECRET);
      const user = getUserById(payload.id);
      if (user) identity = { userId: user.id, name: user.name };
    } catch {}
  }
  if (identity) {
    hubClients.set(ws, identity);
    broadcastOnlineList();
    flushPendingInvite(ws, identity);
  }

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }
    handleMessage(ws, msg);
  });
  ws.on('close', () => handleDisconnect(ws));
  ws.on('error', () => handleDisconnect(ws));
});

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  initDB().then(() => {
    server.listen(PORT, () => console.log(`🕹️  GamesNight hub → http://localhost:${PORT}`));
  });
}

// ── WS message router ───────────────────────────────────────
function handleMessage(ws, msg) {
  try {
    switch (msg.type) {
      case 'invite':          return onInvite(ws, msg);
      case 'invite_response': return onInviteResponse(ws, msg);
      default: send(ws, { type:'error', message:`Unknown: ${msg.type}` });
    }
  } catch (err) {
    console.error('[handleMessage] Unhandled error:', err);
    try { send(ws, { type:'error', message:'An unexpected error occurred. Please try again.' }); } catch {}
  }
}

function onInvite(ws, { toUserId, game }) {
  const from = hubClients.get(ws);
  if (!from) return send(ws, { type:'error', message:'Not authenticated' });
  const gameDef = GAMES.find(g => g.id === game);
  if (!gameDef) return send(ws, { type:'error', message:'Unknown game' });

  const targetWs = findClientByUserId(toUserId);
  if (targetWs) {
    send(targetWs, { type:'invite_received', fromUser:{ id: from.userId, name: from.name }, game });
  } else {
    // Not on the hub page right now — queue it so it replays as a live
    // toast the moment they reconnect, and push-notify them in the meantime.
    pendingInvites.set(toUserId, { fromUserId: from.userId, fromName: from.name, game, ts: Date.now() });
    sendPushToUser(toUserId, {
      title: `${from.name} invited you to play ${gameDef.name}`,
      body:  'Tap to accept.',
      tag:   `gamesnight-invite-${from.userId}`,
      data:  { type:'invite', url:'/' },
    });
  }
  send(ws, { type:'invite_sent', toUserId, game, delivered: !!targetWs });
}

function onInviteResponse(ws, { toUserId, game, accepted }) {
  const from = hubClients.get(ws);
  if (!from) return send(ws, { type:'error', message:'Not authenticated' });
  pendingInvites.delete(from.userId);
  const inviterWs = findClientByUserId(toUserId);

  if (!accepted) {
    if (inviterWs) send(inviterWs, { type:'invite_declined', byUser:{ id: from.userId, name: from.name }, game });
    return;
  }

  // The acceptor is definitely connected right now (they just sent this),
  // so they always take the "creator" role and can proceed immediately —
  // the inviter may have gone offline since sending the original invite.
  const code = generateInviteCode();
  send(ws, { type:'invite_room_ready', code, game, role:'creator' });

  if (inviterWs) {
    send(inviterWs, { type:'invite_room_ready', code, game, role:'joiner' });
    return;
  }
  const gameDef = GAMES.find(g => g.id === game);
  const inviter = getUserById(toUserId);
  if (!gameDef || !inviter) return;
  const joinToken = mintUserJWT(inviter);
  sendPushToUser(toUserId, {
    title: `${from.name} accepted your invite!`,
    body:  `Tap to join your ${gameDef.name} game.`,
    tag:   `gamesnight-invite-${from.userId}`,
    data:  { type:'invite_accepted', url:`${gameDef.url}/sso?token=${encodeURIComponent(joinToken)}&joinRoom=${code}` },
  });
}

function flushPendingInvite(ws, identity) {
  const invite = pendingInvites.get(identity.userId);
  if (!invite) return;
  pendingInvites.delete(identity.userId);
  if (Date.now() - invite.ts > PENDING_INVITE_TTL_MS) return;
  send(ws, { type:'invite_received', fromUser:{ id: invite.fromUserId, name: invite.fromName }, game: invite.game });
}

function findClientByUserId(userId) {
  for (const [ws, meta] of hubClients) {
    if (meta.userId === userId && ws.readyState === WebSocket.OPEN) return ws;
  }
  return null;
}

function broadcastOnlineList() {
  const seen = new Map();
  for (const meta of hubClients.values()) seen.set(meta.userId, meta.name);
  const list = [...seen].map(([id, name]) => ({ id, name }));
  const payload = JSON.stringify({ type:'online_list', users: list });
  for (const ws of hubClients.keys()) {
    if (ws.readyState === WebSocket.OPEN) ws.send(payload);
  }
}

function handleDisconnect(ws) {
  if (!hubClients.has(ws)) return;
  hubClients.delete(ws);
  broadcastOnlineList();
}

function send(ws, data) { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data)); }

function generateInviteCode() {
  return Math.random().toString(36).substr(2,4).toUpperCase();
}

export { app, server };
