import { createHmac } from "node:crypto";

export const UINT64_MAX = (1n << 64n) - 1n;

export class HotpError extends Error {
  constructor(public code: string, message: string) {
    super(`[${code}] ${message}`);
  }
}

/** 解析十进制字符串为 [0, 2^64-1] 的 BigInt 计数器 */
export function parseCounter(input: string | bigint): bigint {
  const s = String(input).trim();
  if (!/^[0-9]+$/.test(s)) {
    throw new HotpError("INVALID_COUNTER", `计数器必须是非负整数十进制字符串: ${s}`);
  }
  const v = BigInt(s);
  if (v < 0n || v > UINT64_MAX) {
    throw new HotpError("INVALID_COUNTER", `计数器超出 uint64 范围: ${s}`);
  }
  return v;
}

/** 计数器编码为恰好 8 字节大端 */
export function encodeCounter(counter: bigint): Buffer {
  if (counter < 0n || counter > UINT64_MAX) {
    throw new HotpError("INVALID_COUNTER", "计数器超出 uint64 范围");
  }
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(counter, 0);
  return buf;
}

/** 解析严格十六进制密钥，限定 16..64 字节 */
export function parseKeyHex(keyHex: string): Buffer {
  const s = keyHex.trim();
  if (!/^[0-9a-fA-F]+$/.test(s) || s.length % 2 !== 0) {
    throw new HotpError("INVALID_KEY_HEX", "密钥必须是偶数长度的十六进制字符串");
  }
  const key = Buffer.from(s, "hex");
  if (key.length < 16 || key.length > 64) {
    throw new HotpError("INVALID_KEY_HEX", `密钥长度须在 16..64 字节之间，当前 ${key.length} 字节`);
  }
  return key;
}

/** RFC 4226 HOTP：HMAC-SHA1 + 动态截取 */
export function hotp(key: Buffer, counter: bigint, digits: 6 | 8): string {
  if (digits !== 6 && digits !== 8) {
    throw new HotpError("INVALID_DIGITS", "位数只支持 6 或 8");
  }
  const msg = encodeCounter(counter);
  const digest = createHmac("sha1", key).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const bin =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  const mod = 10 ** digits;
  return String(bin % mod).padStart(digits, "0");
}
