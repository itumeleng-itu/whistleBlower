import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function openDatabase(file) {
  if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    -- Everything a reporter writes is encrypted on their device; this table
    -- holds only ciphertext. auth_hash is the SHA-256 of a value derived from
    -- the case code, so the code itself is never known to the server.
    -- Dates are stored without a time of day to make timing correlation harder.
    CREATE TABLE IF NOT EXISTS cases (
      id          INTEGER PRIMARY KEY,
      auth_hash   TEXT NOT NULL UNIQUE,
      wrapped_key TEXT NOT NULL,
      report      TEXT NOT NULL,
      status      TEXT NOT NULL DEFAULT 'received',
      created_on  TEXT NOT NULL,
      updated_on  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
      id         INTEGER PRIMARY KEY,
      case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      sender     TEXT NOT NULL CHECK (sender IN ('reporter', 'investigator')),
      body       TEXT NOT NULL,
      created_on TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS messages_case ON messages(case_id);

    -- A fresh random session ID is issued on every login; only its hash is stored.
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash   TEXT PRIMARY KEY,
      role         TEXT NOT NULL CHECK (role IN ('reporter', 'investigator')),
      case_id      INTEGER REFERENCES cases(id) ON DELETE CASCADE,
      expires_at   INTEGER NOT NULL,
      action_count INTEGER NOT NULL DEFAULT 0
    );
  `);
  return db;
}
