/**
 * One-time migration: pull Mah Jong's existing users into the hub's users
 * table. Unlike Azul, Mah Jong's `users.id` is a local AUTOINCREMENT
 * integer, so we don't try to preserve it — a fresh hub id is generated
 * instead, since nothing downstream needs it to match (Mah Jong's own
 * `/sso` route already reconciles accounts by email).
 *
 * Collision handling: if the same email has an account on both Azul and
 * Mah Jong, Azul is treated as canonical — the hub ends up with Azul's
 * password for that email, never Mah Jong's, regardless of which import
 * script runs first. This script never writes back to Mah Jong's own
 * database (no such endpoint exists, deliberately — a remote "overwrite
 * any password hash" endpoint is a standing risk this migration doesn't
 * need). Once the account-unification PR is deployed on Mah Jong, its own
 * `/api/login` proxies to the hub anyway, so its local password column
 * stops being checked at all — the hub being correct is what matters.
 *
 * Usage:
 *   AZUL_URL=https://colmedorno.up.railway.app \
 *   AZUL_ADMIN_EMAIL=you@example.com \
 *   AZUL_ADMIN_PASSWORD=your-password \
 *   MAHJONG_URL=https://traditional-mahjong-production.up.railway.app \
 *   MAHJONG_ADMIN_EMAIL=you@example.com \
 *   MAHJONG_ADMIN_PASSWORD=your-password \
 *   node scripts/import-mahjong-users.js
 */

import { initDB, importUser, getUserByEmail, updateUserPassword } from '../db.js';

const AZUL_URL            = process.env.AZUL_URL;
const AZUL_ADMIN_EMAIL    = process.env.AZUL_ADMIN_EMAIL;
const AZUL_ADMIN_PASSWORD = process.env.AZUL_ADMIN_PASSWORD;
const MAHJONG_URL            = process.env.MAHJONG_URL;
const MAHJONG_ADMIN_EMAIL    = process.env.MAHJONG_ADMIN_EMAIL;
const MAHJONG_ADMIN_PASSWORD = process.env.MAHJONG_ADMIN_PASSWORD;

if (!AZUL_URL || !AZUL_ADMIN_EMAIL || !AZUL_ADMIN_PASSWORD ||
    !MAHJONG_URL || !MAHJONG_ADMIN_EMAIL || !MAHJONG_ADMIN_PASSWORD) {
  console.error('Set AZUL_URL, AZUL_ADMIN_EMAIL, AZUL_ADMIN_PASSWORD, MAHJONG_URL, MAHJONG_ADMIN_EMAIL, MAHJONG_ADMIN_PASSWORD env vars.');
  process.exit(1);
}

function generateId() { return Math.random().toString(36).substr(2, 9); }

async function fetchAzulUsers() {
  const loginRes = await fetch(`${AZUL_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: AZUL_ADMIN_EMAIL, password: AZUL_ADMIN_PASSWORD }),
  });
  if (!loginRes.ok) throw new Error('Login to Azul failed: ' + await loginRes.text());
  const token = (loginRes.headers.get('set-cookie') || '').match(/azul_token=([^;]+)/)?.[1];
  if (!token) throw new Error('Could not extract azul_token from login response.');

  const exportRes = await fetch(`${AZUL_URL}/api/admin/export-users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!exportRes.ok) throw new Error('Azul export failed: ' + await exportRes.text());
  return (await exportRes.json()).users;
}

async function fetchMahjongUsers() {
  const loginRes = await fetch(`${MAHJONG_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: MAHJONG_ADMIN_EMAIL, password: MAHJONG_ADMIN_PASSWORD }),
  });
  if (!loginRes.ok) throw new Error('Login to Mah Jong failed: ' + await loginRes.text());
  // Mah Jong's requireAuth only reads the cookie (no Bearer fallback like
  // Azul's), so the follow-up request needs the raw Cookie header.
  const cookieMatch = (loginRes.headers.get('set-cookie') || '').match(/token=([^;]+)/);
  if (!cookieMatch) throw new Error('Could not extract session token from login response.');

  const exportRes = await fetch(`${MAHJONG_URL}/api/admin/export-users`, {
    headers: { Cookie: `token=${cookieMatch[1]}` },
  });
  if (!exportRes.ok) throw new Error('Mah Jong export failed: ' + await exportRes.text());
  return (await exportRes.json()).users;
}

async function main() {
  await initDB();

  console.log('Fetching Azul users (treated as canonical for any email collision)...');
  const azulUsers   = await fetchAzulUsers();
  const azulByEmail = new Map(azulUsers.map(u => [u.email.toLowerCase(), u]));

  console.log('Fetching Mah Jong users...');
  const mjUsers = await fetchMahjongUsers();

  let imported = 0, reconciled = 0, skipped = 0;
  for (const u of mjUsers) {
    const email     = u.email.toLowerCase();
    const azulMatch = azulByEmail.get(email);
    const existing  = getUserByEmail(email);

    if (azulMatch) {
      // Collision — Azul's password wins in the hub, always, regardless
      // of import order or whatever's currently in the hub for this email.
      if (existing) {
        updateUserPassword(email, azulMatch.password);
        console.log(`Reconciled ${email} — hub now has Azul's password (was already present).`);
      } else {
        importUser({
          id: generateId(), email, name: azulMatch.name, password: azulMatch.password,
          email_verified: false, notify_email: false,
          created: Math.floor(new Date(u.created_at).getTime() / 1000),
        });
        console.log(`Imported ${email} using Azul's password (collision).`);
      }
      reconciled++;
      continue;
    }

    if (existing) {
      console.log(`Skipped ${email} — already exists in the hub (id ${existing.id}), no Azul account to reconcile against.`);
      skipped++;
      continue;
    }

    importUser({
      id: generateId(),
      email,
      name: u.name,
      password: u.password_hash,
      email_verified: false,
      notify_email: false,
      created: Math.floor(new Date(u.created_at).getTime() / 1000),
    });
    console.log(`Imported ${email}`);
    imported++;
  }
  console.log(`Done. ${imported} imported, ${reconciled} collisions reconciled (Azul's password wins), ${skipped} skipped.`);
}

main().catch(err => { console.error(err); process.exit(1); });
