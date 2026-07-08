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
import { initDB, createUser, getUserByEmail, getUserById,
         createOTP, getValidOTP, consumeOTP, updateUserPassword } from './db.js';
import { Resend } from 'resend';

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

const JWT_SECRET = process.env.JWT_SECRET || 'azul-secret-change-in-production';

// ── Games catalog ───────────────────────────────────────────
const GAMES = [
  { id:'azul',    name:'Azul',    icon:'🔷', url: process.env.AZUL_URL    || '' },
  { id:'mahjong', name:'Mah Jong', icon:'🀄', url: process.env.MAHJONG_URL || '' },
].filter(g => g.url);

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

function generateId() { return Math.random().toString(36).substr(2,9); }

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
  res.json({ user: { id:user.id, email:user.email, name:user.name } });
});

app.get('/api/games', (_, res) => {
  res.json({ games: GAMES.map(g => ({ id:g.id, name:g.name, icon:g.icon, url:g.url })) });
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

  const user  = getUserByEmail(payload.email);
  const token = jwt.sign({ id:user.id, email:user.email, name:user.name }, JWT_SECRET, { expiresIn:'30d' });
  setSessionCookie(res, token);
  res.json({ ok:true, user:{ id:user.id, email:user.email, name:user.name } });
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
  if (!targetWs) return send(ws, { type:'error', message:'That player is no longer online.' });

  send(targetWs, { type:'invite_received', fromUser:{ id: from.userId, name: from.name }, game });
}

function onInviteResponse(ws, { toUserId, game, accepted }) {
  const from = hubClients.get(ws);
  if (!from) return send(ws, { type:'error', message:'Not authenticated' });
  const inviterWs = findClientByUserId(toUserId);

  if (!accepted) {
    if (inviterWs) send(inviterWs, { type:'invite_declined', byUser:{ id: from.userId, name: from.name }, game });
    return;
  }
  if (!inviterWs) return send(ws, { type:'error', message:'The inviter is no longer online.' });

  const code = generateInviteCode();
  send(inviterWs, { type:'invite_room_ready', code, game, role:'creator' });
  send(ws,        { type:'invite_room_ready', code, game, role:'joiner' });
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
