import { createHmac, createHash, randomBytes } from "node:crypto";

export const MAX_UINT64 = (1n << 64n) - 1n;
export const RULE_VERSION = "hotp-rfc4226-sha1-v1";

export class HotpError extends Error {
  constructor(public code: string, message: string) {
    super(message);
    this.name = "HotpError";
  }
}

/** 解析十进制计数器字符串为 BigInt，范围 [0, 2^64-1]。 */
export function parseCounter(input: string): bigint {
  if (typeof input !== "string" || !/^(0|[1-9][0-9]*)$/.test(input)) {
    throw new HotpError("INVALID_COUNTER", "计数器必须为非负整数十进制字符串（不允许空格、符号或前导零）");
  }
  const value = BigInt(input);
  if (value > MAX_UINT64) {
    throw new HotpError("COUNTER_OVERFLOW", "计数器超过 uint64 最大值 18446744073709551615");
  }
  return value;
}

/** 将 uint64 计数器编码为恰好 8 字节大端。 */
export function counterToBytes(counter: bigint): Buffer {
  if (counter < 0n || counter > MAX_UINT64) {
    throw new HotpError("COUNTER_OVERFLOW", "计数器超出 uint64 范围");
  }
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(counter, 0);
  return buf;
}

/** 严格十六进制密钥：16..64 字节（即 32..128 个十六进制字符）。 */
export function parseSecretHex(secretHex: string): Buffer {
  if (typeof secretHex !== "string" || !/^[0-9a-fA-F]+$/.test(secretHex)) {
    throw new HotpError("INVALID_SECRET", "密钥必须为纯十六进制字符串");
  }
  if (secretHex.length % 2 !== 0) {
    throw new HotpError("INVALID_SECRET", "密钥十六进制长度必须为偶数");
  }
  const bytes = Buffer.from(secretHex, "hex");
  if (bytes.length < 16 || bytes.length > 64) {
    throw new HotpError("INVALID_SECRET", "密钥长度必须在 16 到 64 字节之间");
  }
  return bytes;
}

export function generateSecretHex(byteLength = 20): string {
  return randomBytes(byteLength).toString("hex");
}

export function secretFingerprint(secret: Buffer): string {
  return createHash("sha256").update(secret).digest("hex").slice(0, 16);
}

export type Digits = 6 | 8;

export function parseDigits(digits: unknown): Digits {
  if (digits === 6 || digits === 8) return digits;
  throw new HotpError("INVALID_DIGITS", "位数只支持 6 或 8");
}

export function parseLookAhead(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 100) {
    throw new HotpError("INVALID_LOOKAHEAD", "前瞻窗口必须为 0 到 100 的整数");
  }
  return value;
}

/**
 * RFC 4226 HOTP：HMAC-SHA1(secret, counter 的 8 字节大端编码)，
 * 动态截取 31 位非负整数后对 10^digits 取余并补前导零。
 */
export function hotp(secret: Buffer, counter: bigint, digits: Digits): string {
  const digest = createHmac("sha1", secret).update(counterToBytes(counter)).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binCode =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  const modulus = digits === 6 ? 1_000_000 : 100_000_000;
  return String(binCode % modulus).padStart(digits, "0");
}

/** 校验待验证口令格式：纯数字、指定位数、无空格。 */
export function validateCodeFormat(code: unknown, digits: Digits): string {
  if (typeof code !== "string" || !new RegExp(`^[0-9]{${digits}}$`).test(code)) {
    throw new HotpError(
      "INVALID_CODE_FORMAT",
      `口令必须为恰好 ${digits} 位数字，不允许空格或其他字符`
    );
  }
  return code;
}
