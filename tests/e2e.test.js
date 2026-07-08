/**
 * GamesNight hub — end-to-end tests: auth, password reset, presence, invites.
 * Spins up the real app/server (imported from server.js) on a separate port.
 *
 * Run with: npm test
 */

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { WebSocket } from 'ws';
import fs from 'fs';
import { server } from '../server.js';
import { initDB } from '../db.js';

const TEST_PORT = 4099;
const BASE_URL  = `http://localhost:${TEST_PORT}`;
const WS_URL    = `ws://localhost:${TEST_PORT}`;

function cookieFrom(res) {
  const raw = res.headers.get('set-cookie') || '';
  return raw.split(';')[0];
}

async function registerAndLogin(email, name, password = 'password123') {
  await fetch(`${BASE_URL}/api/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, name, password }),
  });
  const res = await fetch(`${BASE_URL}/api/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const cookie = cookieFrom(res);
  const { user } = await res.json();
  return { cookie, user };
}

function connectWS(cookie) {
  return new WebSocket(WS_URL, { headers: { cookie } });
}

function waitForMessage(ws, predicate, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for message')), timeoutMs);
    const handler = (raw) => {
      const msg = JSON.parse(raw.toString());
      if (predicate(msg)) {
        clearTimeout(timer);
        ws.off('message', handler);
        resolve(msg);
      }
    };
    ws.on('message', handler);
  });
}

before(async () => {
  if (process.env.DB_PATH && fs.existsSync(process.env.DB_PATH)) fs.unlinkSync(process.env.DB_PATH);
  await initDB();
  await new Promise(resolve => server.listen(TEST_PORT, resolve));
});

after(async () => {
  await new Promise(resolve => server.close(resolve));
});

describe('auth', () => {
  test('register → login → me → logout', async () => {
    const email = `alice-${Date.now()}@example.com`;
    const { cookie, user } = await registerAndLogin(email, 'Alice');
    assert.equal(user.email, email);

    const meRes = await fetch(`${BASE_URL}/api/me`, { headers: { cookie } });
    assert.equal(meRes.status, 200);
    const meData = await meRes.json();
    assert.equal(meData.user.id, user.id);

    const logoutRes = await fetch(`${BASE_URL}/api/logout`, { method: 'POST', headers: { cookie } });
    assert.equal(logoutRes.status, 200);
  });

  test('rejects duplicate email', async () => {
    const email = `bob-${Date.now()}@example.com`;
    await registerAndLogin(email, 'Bob');
    const res = await fetch(`${BASE_URL}/api/register`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, name: 'Bob2', password: 'password123' }),
    });
    assert.equal(res.status, 409);
  });

  test('password reset flow', async () => {
    const email = `carol-${Date.now()}@example.com`;
    await registerAndLogin(email, 'Carol');

    const originalLog = console.log;
    let capturedCode = null;
    console.log = (...args) => {
      const line = args.join(' ');
      const match = line.match(/OTP for .*?:\s*(\d{6})/);
      if (match) capturedCode = match[1];
      originalLog(...args);
    };
    await fetch(`${BASE_URL}/api/forgot-password`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    console.log = originalLog;
    assert.ok(capturedCode, 'expected OTP to be logged in dev mode');

    const otpRes = await fetch(`${BASE_URL}/api/verify-otp`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code: capturedCode }),
    });
    const { resetToken } = await otpRes.json();
    assert.ok(resetToken);

    const resetRes = await fetch(`${BASE_URL}/api/reset-password`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ resetToken, newPassword: 'newpassword456' }),
    });
    assert.equal(resetRes.status, 200);

    const loginRes = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: 'newpassword456' }),
    });
    assert.equal(loginRes.status, 200);
  });
});

describe('presence', () => {
  test('online list reflects connect/disconnect', async () => {
    const a = await registerAndLogin(`dave-${Date.now()}@example.com`, 'Dave');
    const b = await registerAndLogin(`erin-${Date.now()}@example.com`, 'Erin');

    const wsA = connectWS(a.cookie);
    await new Promise(resolve => wsA.on('open', resolve));

    const wsB = connectWS(b.cookie);
    const listMsg = await waitForMessage(wsA, m => m.type === 'online_list' && m.users.some(u => u.id === b.user.id));
    assert.ok(listMsg.users.some(u => u.name === 'Erin'));

    wsB.close();
    const listAfterClose = await waitForMessage(wsA, m => m.type === 'online_list' && !m.users.some(u => u.id === b.user.id));
    assert.ok(!listAfterClose.users.some(u => u.id === b.user.id));

    wsA.close();
  });
});

describe('invites', () => {
  test('invite → accept → both sides get matching room code', async () => {
    const a = await registerAndLogin(`frank-${Date.now()}@example.com`, 'Frank');
    const b = await registerAndLogin(`gina-${Date.now()}@example.com`, 'Gina');

    // No real game URLs configured in test env, so seed one directly via env
    // isn't possible post-import — invites don't require a valid game URL,
    // only a known game id, so this still exercises the full relay.
    const wsA = connectWS(a.cookie);
    const wsB = connectWS(b.cookie);
    await Promise.all([
      new Promise(resolve => wsA.on('open', resolve)),
      new Promise(resolve => wsB.on('open', resolve)),
    ]);

    // Attach listeners before sending, so a fast server response can't
    // arrive before we start listening for it.
    const receivedPromise = waitForMessage(wsB, m => m.type === 'invite_received');
    wsA.send(JSON.stringify({ type: 'invite', toUserId: b.user.id, game: 'azul' }));
    const received = await receivedPromise;
    assert.equal(received.fromUser.id, a.user.id);

    const readyPromiseA = waitForMessage(wsA, m => m.type === 'invite_room_ready');
    const readyPromiseB = waitForMessage(wsB, m => m.type === 'invite_room_ready');
    wsB.send(JSON.stringify({ type: 'invite_response', toUserId: a.user.id, game: 'azul', accepted: true }));
    const [readyA, readyB] = await Promise.all([readyPromiseA, readyPromiseB]);
    assert.equal(readyA.code, readyB.code);
    assert.equal(readyA.role, 'creator');
    assert.equal(readyB.role, 'joiner');

    wsA.close(); wsB.close();
  });
});
