import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { Store, DeviceRow, AuditRow } from "./db.js";
import { hotp, parseCounter, parseKeyHex, HotpError, UINT64_MAX } from "./hotp.js";

export const RULES_VERSION = 1;
export const MAX_LOOK_AHEAD = 100;

export interface VerifyResult {
  requestId: string;
  deviceId: string;
  round: number;
  resultCode: string;
  matched: boolean;
  acceptedCounter?: string;
  prevNextCounter: string;
  newNextCounter: string;
  skipped: number;
  exhausted: boolean;
  replay: boolean;
}

function fingerprint(key: Buffer): string {
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

function now(): string {
  return new Date().toISOString();
}

function paramsHash(parts: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

export class HotpService {
  constructor(private store: Store) {}

  createDevice(input: { name?: string; digits?: number; keyHex: string }) {
    const digits = input.digits ?? 6;
    if (digits !== 6 && digits !== 8) {
      throw new HotpError("INVALID_DIGITS", "位数只支持 6 或 8");
    }
    const key = parseKeyHex(input.keyHex);
    const id = randomUUID();
    this.store.db
      .prepare(
        `INSERT INTO devices (id, name, digits, key_hex, key_fingerprint, next_counter, exhausted, round, rules_version, created_at)
         VALUES (?, ?, ?, ?, ?, '0', 0, 1, ?, ?)`
      )
      .run(id, input.name ?? "test-device", digits, key.toString("hex"), fingerprint(key), RULES_VERSION, now());
    // 密钥仅在创建响应中明文返回一次
    return { id, name: input.name ?? "test-device", digits, keyHex: key.toString("hex"), keyFingerprint: fingerprint(key), rulesVersion: RULES_VERSION };
  }

  private getDeviceRow(id: string): DeviceRow {
    const row = this.store.db.prepare(`SELECT * FROM devices WHERE id = ?`).get(id) as DeviceRow | undefined;
    if (!row) throw new HotpError("DEVICE_NOT_FOUND", `设备不存在: ${id}`);
    return row;
  }

  listDevices() {
    const rows = this.store.db.prepare(`SELECT * FROM devices ORDER BY created_at`).all() as unknown as DeviceRow[];
    return rows.map((r) => this.publicDevice(r));
  }

  private publicDevice(r: DeviceRow) {
    return {
      id: r.id,
      name: r.name,
      digits: r.digits,
      keyFingerprint: r.key_fingerprint,
      nextCounter: r.next_counter,
      exhausted: !!r.exhausted,
      round: r.round,
      rulesVersion: r.rules_version,
      createdAt: r.created_at,
    };
  }

  status(deviceId: string) {
    return this.publicDevice(this.getDeviceRow(deviceId));
  }

  /** 纯计算：指定计数器生成口令，不改变验证器状态 */
  generate(deviceId: string, counterInput: string) {
    const dev = this.getDeviceRow(deviceId);
    const counter = parseCounter(counterInput);
    const code = hotp(Buffer.from(dev.key_hex, "hex"), counter, dev.digits as 6 | 8);
    return { deviceId, counter: counter.toString(), digits: dev.digits, code };
  }

  /** 导出可复算测试向量（含测试密钥，仅供教学复算） */
  exportVectors(deviceId: string, fromInput: string, toInput: string) {
    const dev = this.getDeviceRow(deviceId);
    const from = parseCounter(fromInput);
    const to = parseCounter(toInput);
    if (to < from || to - from > 1000n) {
      throw new HotpError("INVALID_RANGE", "导出范围须为 from<=to 且跨度不超过 1000");
    }
    const key = Buffer.from(dev.key_hex, "hex");
    const vectors: { counter: string; code: string }[] = [];
    for (let c = from; c <= to; c++) {
      vectors.push({ counter: c.toString(), code: hotp(key, c, dev.digits as 6 | 8) });
    }
    return {
      algorithm: "HOTP/HMAC-SHA1 (RFC 4226)",
      deviceId,
      digits: dev.digits,
      keyHex: dev.key_hex,
      keyFingerprint: dev.key_fingerprint,
      vectors,
    };
  }

  /**
   * 验证：在 [nextCounter, nextCounter+lookAhead] 闭区间内从小到大匹配。
   * 整个检查 + 状态推进 + 幂等记录在同一事务中完成。
   */
  verify(deviceId: string, input: { requestId: string; code: string; lookAhead?: number }): VerifyResult {
    const { requestId, code } = input;
    if (!requestId || typeof requestId !== "string") {
      throw new HotpError("INVALID_REQUEST_ID", "requestId 必须是非空字符串");
    }
    const lookAhead = input.lookAhead ?? 0;
    if (!Number.isInteger(lookAhead) || lookAhead < 0 || lookAhead > MAX_LOOK_AHEAD) {
      throw new HotpError("INVALID_LOOK_AHEAD", `前瞻窗口须为 0..${MAX_LOOK_AHEAD} 的整数`);
    }
    const hash = paramsHash({ code, lookAhead });

    this.store.db.exec("BEGIN IMMEDIATE");
    try {
      const dev = this.getDeviceRow(deviceId);

      // 幂等：同一请求 ID 直接返回原结果；参数不同则冲突
      const existing = this.store.db
        .prepare(`SELECT * FROM requests WHERE device_id = ? AND round = ? AND request_id = ?`)
        .get(deviceId, dev.round, requestId) as { params_hash: string; result_json: string } | undefined;
      if (existing) {
        if (existing.params_hash !== hash) {
          throw new HotpError("REQUEST_CONFLICT", `请求 ID ${requestId} 已使用且参数不同`);
        }
        const replayed = JSON.parse(existing.result_json) as VerifyResult;
        replayed.replay = true;
        this.store.db.exec("COMMIT");
        return replayed;
      }

      const prevNext = BigInt(dev.next_counter);
      let resultCode: string;
      let accepted: bigint | null = null;
      let newNext = prevNext;
      let exhausted = !!dev.exhausted;

      if (exhausted) {
        resultCode = "DEVICE_EXHAUSTED";
      } else if (!new RegExp(`^[0-9]{${dev.digits}}$`).test(code)) {
        resultCode = "INVALID_CODE_FORMAT";
      } else {
        const key = Buffer.from(dev.key_hex, "hex");
        const upper = prevNext + BigInt(lookAhead) > UINT64_MAX ? UINT64_MAX : prevNext + BigInt(lookAhead);
        const codeBuf = Buffer.from(code, "utf8");
        for (let c = prevNext; c <= upper; c++) {
          const candidate = Buffer.from(hotp(key, c, dev.digits as 6 | 8), "utf8");
          if (candidate.length === codeBuf.length && timingSafeEqual(candidate, codeBuf)) {
            accepted = c;
            break;
          }
        }
        if (accepted === null) {
          resultCode = "NO_MATCH";
        } else {
          resultCode = "MATCH";
          newNext = accepted + 1n;
          if (accepted === UINT64_MAX) exhausted = true;
          this.store.db
            .prepare(`UPDATE devices SET next_counter = ?, exhausted = ? WHERE id = ?`)
            .run(newNext.toString(), exhausted ? 1 : 0, deviceId);
        }
      }

      const result: VerifyResult = {
        requestId,
        deviceId,
        round: dev.round,
        resultCode,
        matched: accepted !== null,
        ...(accepted !== null ? { acceptedCounter: accepted.toString() } : {}),
        prevNextCounter: prevNext.toString(),
        newNextCounter: newNext.toString(),
        skipped: accepted !== null ? Number(accepted - prevNext) : 0,
        exhausted,
        replay: false,
      };

      this.store.db
        .prepare(`INSERT INTO requests (request_id, device_id, round, params_hash, result_json, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(requestId, deviceId, dev.round, hash, JSON.stringify(result), now());
      this.store.db
        .prepare(
          `INSERT INTO audit (device_id, round, request_id, result_code, accepted_counter, prev_next_counter, new_next_counter, skipped, look_ahead, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(deviceId, dev.round, requestId, resultCode, accepted === null ? null : accepted.toString(), prevNext.toString(), newNext.toString(), result.skipped, lookAhead, now());

      this.store.db.exec("COMMIT");
      return result;
    } catch (err) {
      try {
        this.store.db.exec("ROLLBACK");
      } catch {
        /* 已回滚 */
      }
      throw err;
    }
  }

  /** 脱敏审计记录：不含密钥与提交的口令 */
  audit(deviceId: string): AuditRow[] {
    this.getDeviceRow(deviceId);
    return this.store.db
      .prepare(`SELECT * FROM audit WHERE device_id = ? ORDER BY id`)
      .all(deviceId) as unknown as AuditRow[];
  }

  /** 重置演示：开启新验证轮次，旧轮次记录保留可查 */
  reset(deviceId: string) {
    const dev = this.getDeviceRow(deviceId);
    this.store.db
      .prepare(`UPDATE devices SET next_counter = '0', exhausted = 0, round = round + 1 WHERE id = ?`)
      .run(deviceId);
    return { deviceId, previousRound: dev.round, newRound: dev.round + 1, nextCounter: "0" };
  }
}
