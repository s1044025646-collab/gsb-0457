import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

export interface DeviceRow {
  id: string;
  name: string;
  digits: number;
  key_hex: string;
  key_fingerprint: string;
  next_counter: string;
  exhausted: number;
  round: number;
  rules_version: number;
  created_at: string;
}

export interface AuditRow {
  id: number;
  device_id: string;
  round: number;
  request_id: string;
  result_code: string;
  accepted_counter: string | null;
  prev_next_counter: string;
  new_next_counter: string;
  skipped: number;
  look_ahead: number;
  created_at: string;
}

export interface RequestRow {
  request_id: string;
  device_id: string;
  round: number;
  params_hash: string;
  result_json: string;
  created_at: string;
}

export class Store {
  readonly db: DatabaseSync;

  constructor(dbPath: string) {
    if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        digits INTEGER NOT NULL,
        key_hex TEXT NOT NULL,
        key_fingerprint TEXT NOT NULL,
        next_counter TEXT NOT NULL,
        exhausted INTEGER NOT NULL DEFAULT 0,
        round INTEGER NOT NULL DEFAULT 1,
        rules_version INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS requests (
        request_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        round INTEGER NOT NULL,
        params_hash TEXT NOT NULL,
        result_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (device_id, round, request_id)
      );
      CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        round INTEGER NOT NULL,
        request_id TEXT NOT NULL,
        result_code TEXT NOT NULL,
        accepted_counter TEXT,
        prev_next_counter TEXT NOT NULL,
        new_next_counter TEXT NOT NULL,
        skipped INTEGER NOT NULL,
        look_ahead INTEGER NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
  }

  close(): void {
    this.db.close();
  }
}

export function defaultDbPath(): string {
  return join(process.env.HOTP_DATA_DIR ?? join(process.cwd(), "data"), "hotp.db");
}
