import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import path from "node:path";

export const DATA_DIR = process.env.HOTP_DATA_DIR ?? path.join(process.cwd(), "data");
export const DB_PATH = process.env.HOTP_DB_PATH ?? path.join(DATA_DIR, "hotp.db");

export function openDatabase(dbPath: string = DB_PATH): DatabaseSync {
  if (dbPath !== ":memory:") {
    mkdirSync(path.dirname(dbPath), { recursive: true });
  }
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA busy_timeout = 5000;");
  migrate(db);
  return db;
}

function migrate(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS devices (
      id            TEXT PRIMARY KEY,
      name          TEXT NOT NULL,
      secret_hex    TEXT NOT NULL,
      fingerprint   TEXT NOT NULL,
      digits        INTEGER NOT NULL CHECK (digits IN (6, 8)),
      rule_version  TEXT NOT NULL,
      next_counter  TEXT NOT NULL DEFAULT '0',
      exhausted     INTEGER NOT NULL DEFAULT 0,
      round         INTEGER NOT NULL DEFAULT 1,
      created_at    TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS requests (
      device_id     TEXT NOT NULL REFERENCES devices(id),
      request_id    TEXT NOT NULL,
      payload_hash  TEXT NOT NULL,
      response_json TEXT NOT NULL,
      created_at    TEXT NOT NULL,
      PRIMARY KEY (device_id, request_id)
    );

    CREATE TABLE IF NOT EXISTS audit (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id        TEXT NOT NULL REFERENCES devices(id),
      round            INTEGER NOT NULL,
      request_id       TEXT NOT NULL,
      result           TEXT NOT NULL,
      accepted_counter TEXT,
      prev_next        TEXT NOT NULL,
      new_next         TEXT NOT NULL,
      skipped          TEXT NOT NULL,
      look_ahead       INTEGER NOT NULL,
      created_at       TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_device ON audit(device_id, id);
  `);
}
