import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function openDatabase(file) {
  if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;

    -- Only a hash of each session ID is stored, so a database leak does not
    -- expose usable session IDs. Nothing here identifies a person.
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash   TEXT PRIMARY KEY,
      expires_at   INTEGER NOT NULL,
      report_count INTEGER NOT NULL DEFAULT 0
    );

    -- Reports are deliberately NOT linked to the session that created them,
    -- and only the day of submission is recorded.
    CREATE TABLE IF NOT EXISTS reports (
      id            INTEGER PRIMARY KEY,
      reference     TEXT NOT NULL UNIQUE,
      company       TEXT NOT NULL,
      category      TEXT NOT NULL,
      description   TEXT NOT NULL,
      location      TEXT,
      incident_date TEXT,
      submitted_on  TEXT NOT NULL
    );
  `);
  return db;
}
