import { createHash, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  Digits,
  HotpError,
  MAX_UINT64,
  RULE_VERSION,
  generateSecretHex,
  hotp,
  parseCounter,
  parseDigits,
  parseLookAhead,
  parseSecretHex,
  secretFingerprint,
  validateCodeFormat,
} from "./hotp";

export interface DeviceRow {
  id: string;
  name: string;
  secret_hex: string;
  fingerprint: string;
  digits: number;
  rule_version: string;
  next_counter: string;
  exhausted: number;
  round: number;
  created_at: string;
}

export interface VerifyResult {
  requestId: string;
  result: "ACCEPTED" | "NO_MATCH" | "EXHAUSTED";
  round: number;
  acceptedCounter: string | null;
  prevNext: string;
  newNext: string;
  skipped: string;
  lookAhead: number;
  replayed: boolean;
}

function now(): string {
  return new Date().toISOString();
}

function getDeviceOrThrow(db: DatabaseSync, deviceId: string): DeviceRow {
  const row = db.prepare("SELECT * FROM devices WHERE id = ?").get(deviceId) as DeviceRow | undefined;
  if (!row) throw new HotpError("DEVICE_NOT_FOUND", `设备不存在: ${deviceId}`);
  return row;
}

export function createDevice(
  db: DatabaseSync,
  input: { name?: string; secretHex?: string; digits?: unknown }
): Record<string, unknown> {
  const digits: Digits = parseDigits(input.digits ?? 6);
  const secretHex = input.secretHex ?? generateSecretHex(20);
  const secret = parseSecretHex(secretHex);
  const name = typeof input.name === "string" && input.name.trim() ? input.name.trim() : "test-device";
  const id = randomUUID();
  db.prepare(
    `INSERT INTO devices (id, name, secret_hex, fingerprint, digits, rule_version, next_counter, exhausted, round, created_at)
     VALUES (?, ?, ?, ?, ?, ?, '0', 0, 1, ?)`
  ).run(id, name, secretHex.toLowerCase(), secretFingerprint(secret), digits, RULE_VERSION, now());
  // 仅此创建响应一次性返回完整测试密钥，其余接口只给指纹。
  return {
    id,
    name,
    digits,
    ruleVersion: RULE_VERSION,
    secretHex: secretHex.toLowerCase(),
    fingerprint: secretFingerprint(secret),
    nextCounter: "0",
    round: 1,
    note: "教学用途：完整密钥仅此响应显示一次，请自行保存。",
  };
}

export function listDevices(db: DatabaseSync): Record<string, unknown>[] {
  const rows = db.prepare("SELECT * FROM devices ORDER BY created_at, id").all() as unknown as DeviceRow[];
  return rows.map(maskDevice);
}

function maskDevice(row: DeviceRow): Record<string, unknown> {
  return {
    id: row.id,
    name: row.name,
    digits: row.digits,
    ruleVersion: row.rule_version,
    fingerprint: row.fingerprint,
    nextCounter: row.next_counter,
    exhausted: !!row.exhausted,
    round: row.round,
    createdAt: row.created_at,
  };
}

export function getVerifierState(db: DatabaseSync, deviceId: string): Record<string, unknown> {
  return maskDevice(getDeviceOrThrow(db, deviceId));
}

/** 纯计算：生成指定计数器的口令，不改变验证器状态。 */
export function generateToken(db: DatabaseSync, deviceId: string, counterInput: string): Record<string, unknown> {
  const row = getDeviceOrThrow(db, deviceId);
  const counter = parseCounter(counterInput);
  const secret = Buffer.from(row.secret_hex, "hex");
  return {
    deviceId: row.id,
    counter: counter.toString(),
    digits: row.digits,
    code: hotp(secret, counter, row.digits as Digits),
    note: "纯计算，验证器 nextCounter 未改变。",
  };
}

export function exportTestVectors(
  db: DatabaseSync,
  deviceId: string,
  fromInput: string,
  count: number
): Record<string, unknown> {
  const row = getDeviceOrThrow(db, deviceId);
  const from = parseCounter(fromInput);
  if (!Number.isInteger(count) || count < 1 || count > 100) {
    throw new HotpError("INVALID_COUNT", "向量数量必须为 1 到 100 的整数");
  }
  const secret = Buffer.from(row.secret_hex, "hex");
  const vectors: { counter: string; code: string }[] = [];
  for (let i = 0n; i < BigInt(count); i++) {
    const c = from + i;
    if (c > MAX_UINT64) break;
    vectors.push({ counter: c.toString(), code: hotp(secret, c, row.digits as Digits) });
  }
  return {
    deviceId: row.id,
    digits: row.digits,
    ruleVersion: row.rule_version,
    fingerprint: row.fingerprint,
    vectors,
  };
}

function payloadHash(code: string, lookAhead: number): string {
  return createHash("sha256").update(JSON.stringify({ code, lookAhead })).digest("hex");
}

export function verify(
  db: DatabaseSync,
  deviceId: string,
  input: { requestId?: unknown; code?: unknown; lookAhead?: unknown }
): VerifyResult {
  if (typeof input.requestId !== "string" || input.requestId.length === 0 || input.requestId.length > 128) {
    throw new HotpError("INVALID_REQUEST_ID", "requestId 必须为 1 到 128 字符的字符串");
  }
  const requestId = input.requestId;
  const lookAhead = parseLookAhead(input.lookAhead ?? 0);

  db.exec("BEGIN IMMEDIATE");
  try {
    const row = getDeviceOrThrow(db, deviceId);
    const code = validateCodeFormat(input.code, row.digits as Digits);
    const hash = payloadHash(code, lookAhead);

    const existing = db
      .prepare("SELECT payload_hash, response_json FROM requests WHERE device_id = ? AND request_id = ?")
      .get(deviceId, requestId) as { payload_hash: string; response_json: string } | undefined;
    if (existing) {
      if (existing.payload_hash !== hash) {
        throw new HotpError("REQUEST_CONFLICT", `请求 ID ${requestId} 已以不同参数使用过`);
      }
      const stored = JSON.parse(existing.response_json) as VerifyResult;
      db.exec("COMMIT");
      return { ...stored, replayed: true };
    }

    const prevNext = BigInt(row.next_counter);
    let result: VerifyResult["result"] = "NO_MATCH";
    let acceptedCounter: bigint | null = null;
    let newNext = prevNext;

    if (row.exhausted) {
      result = "EXHAUSTED";
    } else {
      const secret = Buffer.from(row.secret_hex, "hex");
      const windowEnd = prevNext + BigInt(lookAhead) > MAX_UINT64 ? MAX_UINT64 : prevNext + BigInt(lookAhead);
      for (let c = prevNext; c <= windowEnd; c++) {
        if (hotp(secret, c, row.digits as Digits) === code) {
          result = "ACCEPTED";
          acceptedCounter = c;
          break;
        }
      }
    }

    let exhausted = row.exhausted;
    if (result === "ACCEPTED" && acceptedCounter !== null) {
      if (acceptedCounter === MAX_UINT64) {
        exhausted = 1;
        newNext = MAX_UINT64;
      } else {
        newNext = acceptedCounter + 1n;
      }
      db.prepare("UPDATE devices SET next_counter = ?, exhausted = ? WHERE id = ?").run(
        newNext.toString(),
        exhausted,
        deviceId
      );
    }

    const skipped = acceptedCounter !== null ? acceptedCounter - prevNext : 0n;
    const response: VerifyResult = {
      requestId,
      result,
      round: row.round,
      acceptedCounter: acceptedCounter !== null ? acceptedCounter.toString() : null,
      prevNext: prevNext.toString(),
      newNext: newNext.toString(),
      skipped: skipped.toString(),
      lookAhead,
      replayed: false,
    };

    db.prepare(
      `INSERT INTO audit (device_id, round, request_id, result, accepted_counter, prev_next, new_next, skipped, look_ahead, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      deviceId,
      row.round,
      requestId,
      result,
      response.acceptedCounter,
      response.prevNext,
      response.newNext,
      response.skipped,
      lookAhead,
      now()
    );
    db.prepare(
      "INSERT INTO requests (device_id, request_id, payload_hash, response_json, created_at) VALUES (?, ?, ?, ?, ?)"
    ).run(deviceId, requestId, hash, JSON.stringify(response), now());

    db.exec("COMMIT");
    return response;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      /* already rolled back */
    }
    throw err;
  }
}

export function listAudit(db: DatabaseSync, deviceId: string): Record<string, unknown>[] {
  getDeviceOrThrow(db, deviceId);
  const rows = db
    .prepare("SELECT * FROM audit WHERE device_id = ? ORDER BY id")
    .all(deviceId) as Record<string, unknown>[];
  // 审计记录不含完整密钥与待验证口令明文。
  return rows.map((r) => ({
    id: r.id,
    round: r.round,
    requestId: r.request_id,
    result: r.result,
    acceptedCounter: r.accepted_counter,
    prevNext: r.prev_next,
    newNext: r.new_next,
    skipped: r.skipped,
    lookAhead: r.look_ahead,
    createdAt: r.created_at,
  }));
}

/** 重置演示：开启新验证轮次，nextCounter 归零；旧轮次审计记录保留可查。 */
export function resetDevice(db: DatabaseSync, deviceId: string): Record<string, unknown> {
  db.exec("BEGIN IMMEDIATE");
  try {
    const row = getDeviceOrThrow(db, deviceId);
    const newRound = row.round + 1;
    db.prepare("UPDATE devices SET next_counter = '0', exhausted = 0, round = ? WHERE id = ?").run(
      newRound,
      deviceId
    );
    db.exec("COMMIT");
    return {
      deviceId,
      round: newRound,
      previousRound: row.round,
      nextCounter: "0",
      note: "已开启新验证轮次；旧轮次记录仍可在审计中查询，并非原轮次倒退。",
    };
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      /* ignore */
    }
    throw err;
  }
}
