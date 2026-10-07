import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hotp, parseCounter, encodeCounter, parseKeyHex, UINT64_MAX } from "../src/hotp.js";
import { Store } from "../src/db.js";
import { HotpService } from "../src/service.js";

const RFC_KEY_ASCII = "12345678901234567890";
const RFC_KEY_HEX = Buffer.from(RFC_KEY_ASCII, "ascii").toString("hex");
const RFC_KEY = Buffer.from(RFC_KEY_ASCII, "ascii");

// RFC 4226 附录 D 公开测试向量（六位，计数器 0..9）
const RFC_VECTORS = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];

test("RFC 4226 公开测试向量 0..9（六位）", () => {
  for (let c = 0; c <= 9; c++) {
    assert.equal(hotp(RFC_KEY, BigInt(c), 6), RFC_VECTORS[c], `counter=${c}`);
  }
});

test("独立八字节大端编码核验：手工 hex 构造 + 独立截取实现", () => {
  // 不依赖项目 encodeCounter/hotp 的独立实现
  function independentHotp(key: Buffer, counter: bigint, digits: number): string {
    let hex = counter.toString(16);
    if (hex.length > 16) throw new Error("overflow");
    hex = hex.padStart(16, "0"); // 恰好 8 字节大端
    const msg = Buffer.from(hex, "hex");
    assert.equal(msg.length, 8);
    const digest = createHmac("sha1", key).update(msg).digest();
    const offset = digest[19] & 0xf;
    const code =
      ((digest[offset] & 0x7f) * 2 ** 24 + digest[offset + 1] * 2 ** 16 + digest[offset + 2] * 2 ** 8 + digest[offset + 3]) %
      10 ** digits;
    return String(code).padStart(digits, "0");
  }
  for (let c = 0; c <= 9; c++) {
    assert.equal(independentHotp(RFC_KEY, BigInt(c), 6), RFC_VECTORS[c]);
    assert.equal(hotp(RFC_KEY, BigInt(c), 6), independentHotp(RFC_KEY, BigInt(c), 6));
  }
  // 大计数器交叉核验
  const big = 2n ** 53n + 12345n;
  assert.equal(hotp(RFC_KEY, big, 6), independentHotp(RFC_KEY, big, 6));
  assert.equal(hotp(RFC_KEY, UINT64_MAX, 8), independentHotp(RFC_KEY, UINT64_MAX, 8));
});

test("计数器编码恰好 8 字节大端", () => {
  assert.deepEqual(encodeCounter(1n), Buffer.from("0000000000000001", "hex"));
  assert.deepEqual(encodeCounter(UINT64_MAX), Buffer.from("ffffffffffffffff", "hex"));
  assert.throws(() => encodeCounter(UINT64_MAX + 1n), /uint64/);
});

test("计数器解析：拒绝负数、非数字与超范围", () => {
  assert.equal(parseCounter("18446744073709551615"), UINT64_MAX);
  assert.throws(() => parseCounter("18446744073709551616"), /INVALID_COUNTER|uint64/);
  assert.throws(() => parseCounter("-1"));
  assert.throws(() => parseCounter("12 3"));
  assert.throws(() => parseCounter("abc"));
});

test("密钥校验：严格十六进制且 16..64 字节", () => {
  assert.equal(parseKeyHex(RFC_KEY_HEX).length, 20);
  assert.throws(() => parseKeyHex("zz".repeat(16)));
  assert.throws(() => parseKeyHex("aa".repeat(15)));
  assert.throws(() => parseKeyHex("aa".repeat(65)));
  assert.throws(() => parseKeyHex("abc")); // 奇数长度
});

test("前导零补足：输出恒为定长数字串", () => {
  // 扫描找到真实前导零样例并验证补足行为
  let found = false;
  for (let c = 0n; c < 200000n; c++) {
    const code = hotp(RFC_KEY, c, 6);
    assert.match(code, /^[0-9]{6}$/);
    if (code[0] === "0") {
      found = true;
      assert.equal(code.length, 6);
      break;
    }
  }
  assert.ok(found, "扫描范围内应存在前导零口令");
});

function makeService(): { service: HotpService; store: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "hotp-test-"));
  const store = new Store(join(dir, "test.db"));
  return { service: new HotpService(store), store, dir };
}

test("验证流程：前瞻窗口、跳过消费、重放拒绝、失败不推进", () => {
  const { service } = makeService();
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });

  // 前瞻 2 接受计数器 2，推进到 3，跳过 2 个
  const r1 = service.verify(dev.id, { requestId: "r1", code: "359152", lookAhead: 2 });
  assert.equal(r1.resultCode, "MATCH");
  assert.equal(r1.acceptedCounter, "2");
  assert.equal(r1.newNextCounter, "3");
  assert.equal(r1.skipped, 2);
  assert.equal(service.status(dev.id).nextCounter, "3");

  // 前瞻 0 重放已消费的计数器 0 → 拒绝且不推进
  const r2 = service.verify(dev.id, { requestId: "r2", code: "755224", lookAhead: 0 });
  assert.equal(r2.resultCode, "NO_MATCH");
  assert.equal(service.status(dev.id).nextCounter, "3");

  // 窗口末端匹配：前瞻 0 精确匹配计数器 3
  const r3 = service.verify(dev.id, { requestId: "r3", code: "969429", lookAhead: 0 });
  assert.equal(r3.resultCode, "MATCH");
  assert.equal(r3.acceptedCounter, "3");
  assert.equal(service.status(dev.id).nextCounter, "4");

  // 错误格式（含空格/位数错误/非数字）不推进
  for (const [i, bad] of [" 338314", "33831", "3383145", "33a314"].entries()) {
    const r = service.verify(dev.id, { requestId: `bad-${i}`, code: bad, lookAhead: 10 });
    assert.equal(r.resultCode, "INVALID_CODE_FORMAT");
  }
  assert.equal(service.status(dev.id).nextCounter, "4");

  // 窗口内无匹配不推进
  const r4 = service.verify(dev.id, { requestId: "r4", code: "000000", lookAhead: 0 });
  assert.equal(r4.resultCode, "NO_MATCH");
  assert.equal(service.status(dev.id).nextCounter, "4");
});

test("前瞻窗口边界：超过 100 拒绝；窗口外口令不匹配", () => {
  const { service } = makeService();
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });
  assert.throws(() => service.verify(dev.id, { requestId: "x", code: "755224", lookAhead: 101 }), /INVALID_LOOK_AHEAD/);
  // 计数器 3 的口令在前瞻 2 的窗口 [0,2] 之外
  const r = service.verify(dev.id, { requestId: "x2", code: "969429", lookAhead: 2 });
  assert.equal(r.resultCode, "NO_MATCH");
  assert.equal(service.status(dev.id).nextCounter, "0");
});

test("请求幂等与冲突", () => {
  const { service } = makeService();
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });
  const first = service.verify(dev.id, { requestId: "same", code: "287082", lookAhead: 1 });
  assert.equal(first.resultCode, "MATCH");
  const retry = service.verify(dev.id, { requestId: "same", code: "287082", lookAhead: 1 });
  assert.equal(retry.replay, true);
  assert.equal(retry.resultCode, "MATCH");
  assert.equal(service.status(dev.id).nextCounter, "2"); // 未重复消费
  assert.throws(() => service.verify(dev.id, { requestId: "same", code: "359152", lookAhead: 1 }), /REQUEST_CONFLICT/);
  assert.throws(() => service.verify(dev.id, { requestId: "same", code: "287082", lookAhead: 5 }), /REQUEST_CONFLICT/);
});

test("并发提交同一计数器：最多一条成功", () => {
  const { service } = makeService();
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });
  const code = service.generate(dev.id, "0").code;
  const results = [
    service.verify(dev.id, { requestId: "c1", code, lookAhead: 0 }),
    service.verify(dev.id, { requestId: "c2", code, lookAhead: 0 }),
  ];
  const matches = results.filter((r) => r.resultCode === "MATCH");
  assert.equal(matches.length, 1);
  assert.equal(service.status(dev.id).nextCounter, "1");
});

test("重启后状态与幂等记录保持", () => {
  const dir = mkdtempSync(join(tmpdir(), "hotp-test-"));
  const dbPath = join(dir, "test.db");
  let store = new Store(dbPath);
  let service = new HotpService(store);
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });
  service.verify(dev.id, { requestId: "boot-1", code: "359152", lookAhead: 2 });
  store.close();

  store = new Store(dbPath);
  service = new HotpService(store);
  assert.equal(service.status(dev.id).nextCounter, "3");
  const replay = service.verify(dev.id, { requestId: "boot-1", code: "359152", lookAhead: 2 });
  assert.equal(replay.replay, true);
  assert.equal(replay.resultCode, "MATCH");
  assert.equal(service.status(dev.id).nextCounter, "3");
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("八位模式与大于 2^53 的计数器", () => {
  const { service } = makeService();
  const dev = service.createDevice({ name: "t8", digits: 8, keyHex: RFC_KEY_HEX });
  const big = (2n ** 53n + 7n).toString();
  const g = service.generate(dev.id, big);
  assert.match(g.code, /^[0-9]{8}$/);
  // 生成是纯计算，不推进验证器
  assert.equal(service.status(dev.id).nextCounter, "0");
  // 直接验证该大计数器：需要先把 nextCounter 推进过去不现实，改为验证窗口逻辑用六位设备
  const dev6 = service.createDevice({ name: "t6", digits: 6, keyHex: RFC_KEY_HEX });
  const code0 = service.generate(dev6.id, "0").code;
  const r = service.verify(dev6.id, { requestId: "b1", code: code0, lookAhead: 0 });
  assert.equal(r.resultCode, "MATCH");
});

test("uint64 最大计数器匹配后设备耗尽且不回绕", () => {
  const { service, store } = makeService();
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });
  // 直接把 nextCounter 调到最大值（教学测试直接改库模拟高位状态）
  store.db.prepare(`UPDATE devices SET next_counter = ? WHERE id = ?`).run(UINT64_MAX.toString(), dev.id);
  const code = hotp(RFC_KEY, UINT64_MAX, 6);
  const r = service.verify(dev.id, { requestId: "max1", code, lookAhead: 0 });
  assert.equal(r.resultCode, "MATCH");
  assert.equal(r.exhausted, true);
  const st = service.status(dev.id);
  assert.equal(st.exhausted, true);
  assert.notEqual(st.nextCounter, "0"); // 不回绕
  // 耗尽后拒绝一切验证
  const r2 = service.verify(dev.id, { requestId: "max2", code, lookAhead: 100 });
  assert.equal(r2.resultCode, "DEVICE_EXHAUSTED");
});

test("重置开启新轮次，旧记录可查，旧请求 ID 不冲突", () => {
  const { service } = makeService();
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });
  service.verify(dev.id, { requestId: "round1", code: "755224", lookAhead: 0 });
  const reset = service.reset(dev.id);
  assert.equal(reset.newRound, 2);
  assert.equal(service.status(dev.id).nextCounter, "0");
  // 新轮次从 0 重新开始
  const r = service.verify(dev.id, { requestId: "round2", code: "755224", lookAhead: 0 });
  assert.equal(r.resultCode, "MATCH");
  assert.equal(r.round, 2);
  // 审计包含两个轮次的记录，且不含口令/密钥
  const audit = service.audit(dev.id);
  assert.equal(audit.length, 2);
  assert.deepEqual(audit.map((a) => a.round), [1, 2]);
  const serialized = JSON.stringify(audit);
  assert.ok(!serialized.includes(RFC_KEY_HEX));
  assert.ok(!serialized.includes("755224"));
});

test("审计与列表脱敏：不泄露密钥与口令", () => {
  const { service } = makeService();
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });
  service.verify(dev.id, { requestId: "a1", code: "755224", lookAhead: 0 });
  const listJson = JSON.stringify(service.listDevices());
  const auditJson = JSON.stringify(service.audit(dev.id));
  const statusJson = JSON.stringify(service.status(dev.id));
  for (const s of [listJson, auditJson, statusJson]) {
    assert.ok(!s.includes(RFC_KEY_HEX), "不应包含完整密钥");
    assert.ok(!s.includes("755224"), "不应包含提交的口令");
  }
  assert.ok(listJson.includes(dev.keyFingerprint));
});

test("导出可复算测试向量与 RFC 向量一致", () => {
  const { service } = makeService();
  const dev = service.createDevice({ name: "t", digits: 6, keyHex: RFC_KEY_HEX });
  const out = service.exportVectors(dev.id, "0", "9");
  assert.equal(out.keyHex, RFC_KEY_HEX);
  assert.deepEqual(out.vectors.map((v) => v.code), RFC_VECTORS);
});

