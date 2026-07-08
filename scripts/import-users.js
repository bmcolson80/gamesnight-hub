/**
 * One-time migration: pull Azul's existing users into the hub's users table,
 * preserving `id` so Azul's game_players.user_id / players[].userId keep
 * resolving after the switch to hub-issued logins.
 *
 * Usage:
 *   AZUL_URL=https://azul.up.railway.app \
 *   AZUL_ADMIN_EMAIL=you@example.com \
 *   AZUL_ADMIN_PASSWORD=your-password \
 *   node scripts/import-users.js
 */

import { initDB, importUser } from '../db.js';

const AZUL_URL      = process.env.AZUL_URL;
const ADMIN_EMAIL    = process.env.AZUL_ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.AZUL_ADMIN_PASSWORD;

if (!AZUL_URL || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error('Set AZUL_URL, AZUL_ADMIN_EMAIL, AZUL_ADMIN_PASSWORD env vars.');
  process.exit(1);
}

async function main() {
  await initDB();

  const loginRes = await fetch(`${AZUL_URL}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
  });
  if (!loginRes.ok) {
    console.error('Login to Azul failed:', await loginRes.text());
    process.exit(1);
  }
  const setCookie = loginRes.headers.get('set-cookie') || '';
  const token = setCookie.match(/azul_token=([^;]+)/)?.[1];
  if (!token) {
    console.error('Could not extract azul_token from login response.');
    process.exit(1);
  }

  const exportRes = await fetch(`${AZUL_URL}/api/admin/export-users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!exportRes.ok) {
    console.error('Export failed:', await exportRes.text());
    process.exit(1);
  }
  const { users } = await exportRes.json();

  for (const u of users) {
    importUser(u);
    console.log(`Imported ${u.email} (${u.id})`);
  }
  console.log(`Done. ${users.length} users processed.`);
}

main().catch(err => { console.error(err); process.exit(1); });
