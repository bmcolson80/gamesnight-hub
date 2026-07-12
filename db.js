/**
 * db.js — Persistent storage using sql.js (pure JS SQLite)
 * Saves to disk as gamesnight.db in the project root
 */

import initSqlJs from 'sql.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH   = process.env.DB_PATH ?? path.join(__dirname, 'gamesnight.db');

let db = null;

// ── Init ──────────────────────────────────────────────────
export async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id                  TEXT PRIMARY KEY,
      email               TEXT UNIQUE NOT NULL,
      name                TEXT NOT NULL,
      password            TEXT NOT NULL,
      email_verified      INTEGER NOT NULL DEFAULT 0,
      notify_email        INTEGER NOT NULL DEFAULT 0,
      created             INTEGER DEFAULT (strftime('%s','now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS otp_requests (
      id         TEXT PRIMARY KEY,
      email      TEXT NOT NULL,
      code       TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used       INTEGER NOT NULL DEFAULT 0,
      created    INTEGER DEFAULT (strftime('%s','now'))
    )
  `);

  save();
  console.log('📦 Database ready');
}

// ── Persist to disk ───────────────────────────────────────
export function save() {
  if (!db) return;
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// ── Users ─────────────────────────────────────────────────
export function createUser({ id, email, name, password }) {
  db.run(
    'INSERT INTO users (id, email, name, password) VALUES (?, ?, ?, ?)',
    [id, email.toLowerCase().trim(), name.trim(), password]
  );
  save();
}

export function importUser({ id, email, name, password, email_verified, notify_email, created }) {
  db.run(`
    INSERT INTO users (id, email, name, password, email_verified, notify_email, created)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO NOTHING
  `, [id, email.toLowerCase().trim(), name, password, email_verified ? 1 : 0, notify_email ? 1 : 0, created]);
  save();
}

export function getUserByEmail(email) {
  const res = db.exec('SELECT * FROM users WHERE email = ?', [email.toLowerCase().trim()]);
  if (!res.length || !res[0].values.length) return null;
  return rowToObj(res[0]);
}

export function getUserById(id) {
  const res = db.exec('SELECT * FROM users WHERE id = ?', [id]);
  if (!res.length || !res[0].values.length) return null;
  return rowToObj(res[0]);
}

export function getAllUsers() {
  const res = db.exec('SELECT * FROM users ORDER BY created DESC');
  if (!res.length) return [];
  return res[0].values.map(row => zipRow(res[0].columns, row));
}

export function updateUserPassword(email, hashedPassword) {
  db.run("UPDATE users SET password=? WHERE email=?", [hashedPassword, email.toLowerCase().trim()]);
  save();
}

// Create-or-update by email, used to replicate an account created/changed on
// a sibling game so every app converges on the same password.
export function upsertUser({ id, email, name, password }) {
  const normalizedEmail = email.toLowerCase().trim();
  const existing = getUserByEmail(normalizedEmail);
  if (existing) {
    db.run('UPDATE users SET name=?, password=? WHERE email=?', [name, password, normalizedEmail]);
  } else {
    db.run(
      'INSERT INTO users (id, email, name, password) VALUES (?, ?, ?, ?)',
      [id, normalizedEmail, name, password]
    );
  }
  save();
}

// ── OTP / Password reset ─────────────────────────────────
export function createOTP({ id, email, code, expiresAt }) {
  db.run("UPDATE otp_requests SET used=1 WHERE email=? AND used=0", [email.toLowerCase().trim()]);
  db.run(
    'INSERT INTO otp_requests (id, email, code, expires_at) VALUES (?,?,?,?)',
    [id, email.toLowerCase().trim(), code, expiresAt]
  );
  save();
}

export function getValidOTP(email, code) {
  const now = Math.floor(Date.now() / 1000);
  const res = db.exec(
    'SELECT * FROM otp_requests WHERE email=? AND code=? AND used=0 AND expires_at > ? ORDER BY created DESC LIMIT 1',
    [email.toLowerCase().trim(), code, now]
  );
  if (!res.length || !res[0].values.length) return null;
  return rowToObj(res[0]);
}

export function consumeOTP(id) {
  db.run("UPDATE otp_requests SET used=1 WHERE id=?", [id]);
  save();
}

// ── Helpers ───────────────────────────────────────────────
function rowToObj(result) {
  if (!result.values.length) return null;
  return zipRow(result.columns, result.values[0]);
}

function zipRow(columns, values) {
  const obj = {};
  columns.forEach((col, i) => { obj[col] = values[i]; });
  return obj;
}
