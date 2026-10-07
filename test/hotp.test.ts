import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { openDatabase } from "../src/db";
import { hotp, parseCounter, counterToBytes, MAX_UINT64, HotpError } from "../src/hotp";
import * as svc from "../src/service";
import { startServer } from "../src/server";

// RFC 4226 Appendix D 公开测试向量，密钥为 ASCII "12345678901234567890"
const RFC_SECRET_HEX = "3132333435363738393031323334353637383930";
const RFC_SECRET = Buffer.from(RFC_SECRET_HEX, "hex");
const RFC_VECTORS = [
  "755224", "287082", "359152", "969429", "338314",
  "254676", "287922", "162583", "399871", "520489",
];

test("RFC 4226 计数器 0..9 六位公开测试向量", () => {
  for (let i = 0; i < 10; i++) {
    assert.equal(hotp(RFC_SECRET, BigInt(i), 6), RFC_VECTORS[i], `counter=${i}`);
  }
});

test("独立核验：计数器编码为恰好 8 字节大端", () => {
  assert.deepEqual([...counterToBytes(0n)], [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual([...counterToBytes(1n)], [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual([...counterToBytes(0x0102030405060708n)], [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.equal(counterToBytes(MAX_UINT64).toString("hex"), "ffffffffffffffff");
});

test("独立核验：HMAC-SHA1 中间摘要与公开值一致（非本项目生成）", () => {
  // 经独立实现（.NET HMACSHA1）交叉核验的 HMAC-SHA1 中间摘要
  const known: [bigint, string][] = [
    [0n, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"],
    [1n, "75a48a19d4cbe100644e8ac1397eea747a2d33ab"],
    [2n, "0bacb7fa082fef30782211938bc1c5e70416ff44"],
  ];
  for (const [counter, expectedHex] of known) {
    const digest = createHmac("sha1", RFC_SECRET).update(counterToBytes(counter)).digest("hex");
    assert.equal(digest, expectedHex, `counter=${counter}`);
  }
});

test("计数器文本或小端编码不能当作 HMAC 消息（反向构造应失败）", () => {
  const asText = createHmac("sha1", RFC_SECRET).update("1", "utf8").digest();
  const littleEndian = Buffer.alloc(8);
  littleEndian.writeBigUInt64LE(1n);
  const asLE = createHmac("sha1", RFC_SECRET).update(littleEndian).digest();
  const correct = createHmac("sha1", RFC_SECRET).update(counterToBytes(1n)).digest();
  assert.notDeepEqual(asText, correct);
  assert.notDeepEqual(asLE, correct);
});

test("前导零：输出始终补足固定位数", () => {
  let sawLeadingZero = false;
  for (let c = 0n; c < 20000n; c++) {
    const code = hotp(RFC_SECRET, c, 6);
    assert.match(code, /^[0-9]{6}$/);
    if (code.startsWith("0")) sawLeadingZero = true;
  }
  assert.ok(sawLeadingZero, "两万次采样中应出现前导零口令");
});

test("八位模式：与六位模式同源且低六位一致", () => {
  for (let c = 0n; c < 50n; c++) {
    const c6 = hotp(RFC_SECRET, c, 6);
    const c8 = hotp(RFC_SECRET, c, 8);
    assert.match(c8, /^[0-9]{8}$/);
    assert.ok(c8.endsWith(c6), `counter=${c}: ${c8} 应以 ${c6} 结尾`);
  }
});

test("大于 2^53 的计数器使用 BigInt 精确计算", () => {
  const a = parseCounter("9007199254740993"); // 2^53 + 1
  const b = parseCounter("9007199254740992"); // 2^53
  assert.notEqual(hotp(RFC_SECRET, a, 6), hotp(RFC_SECRET, b, 6));
  assert.equal(parseCounter(MAX_UINT64.toString()), MAX_UINT64);
  assert.throws(() => parseCounter("18446744073709551616"), HotpError);
  assert.throws(() => parseCounter("-1"), HotpError);
  assert.throws(() => parseCounter(" 12"), HotpError);
  assert.throws(() => parseCounter("01"), HotpError);
});

function memDb() {
  return openDatabase(":memory:");
}

function makeDevice(db: ReturnType<typeof memDb>, digits = 6): string {
  const d = svc.createDevice(db, { name: "t", secretHex: RFC_SECRET_HEX, digits }) as { id: string };
  return d.id;
}

test("前瞻窗口：从 0 开始以前瞻 2 接受计数器 2 并推进到 3", () => {
  const db = memDb();
  const id = makeDevice(db);
  const r = svc.verify(db, id, { requestId: "r1", code: "359152", lookAhead: 2 });
  assert.equal(r.result, "ACCEPTED");
  assert.equal(r.acceptedCounter, "2");
  assert.equal(r.prevNext, "0");
  assert.equal(r.newNext, "3");
  assert.equal(r.skipped, "2");
});

test("前瞻 0 拒绝已消费的计数器（重放测试）", () => {
  const db = memDb();
  const id = makeDevice(db);
  svc.verify(db, id, { requestId: "a", code: "755224", lookAhead: 0 }); // 消费 0
  const replay = svc.verify(db, id, { requestId: "b", code: "755224", lookAhead: 0 });
  assert.equal(replay.result, "NO_MATCH");
  assert.equal(replay.newNext, "1");
});

test("窗口末端匹配与窗口外拒绝", () => {
  const db = memDb();
  const id = makeDevice(db);
  // 窗口 [0,2]，计数器 3 的口令应被拒绝且不推进
  const outside = svc.verify(db, id, { requestId: "w1", code: "969429", lookAhead: 2 });
  assert.equal(outside.result, "NO_MATCH");
  assert.equal(outside.newNext, "0");
  // 窗口末端（计数器 2）可接受
  const edge = svc.verify(db, id, { requestId: "w2", code: "359152", lookAhead: 2 });
  assert.equal(edge.result, "ACCEPTED");
  assert.equal(edge.acceptedCounter, "2");
});

test("失败不推进：错误口令、含空格、位数错误均不改变状态", () => {
  const db = memDb();
  const id = makeDevice(db);
  const bad = svc.verify(db, id, { requestId: "f1", code: "000000", lookAhead: 5 });
  assert.equal(bad.result, "NO_MATCH");
  assert.throws(
    () => svc.verify(db, id, { requestId: "f2", code: " 755224", lookAhead: 0 }),
    (e: unknown) => e instanceof HotpError && (e as HotpError).code === "INVALID_CODE_FORMAT"
  );
  assert.throws(() => svc.verify(db, id, { requestId: "f3", code: "75522", lookAhead: 0 }), HotpError);
  assert.throws(() => svc.verify(db, id, { requestId: "f4", code: "abcdef", lookAhead: 0 }), HotpError);
  const state = svc.getVerifierState(db, id) as { nextCounter: string };
  assert.equal(state.nextCounter, "0");
});

test("请求幂等：相同请求重试返回原结果不重复消费，不同参数报冲突", () => {
  const db = memDb();
  const id = makeDevice(db);
  const first = svc.verify(db, id, { requestId: "idem-1", code: "755224", lookAhead: 0 });
  assert.equal(first.result, "ACCEPTED");
  const retry = svc.verify(db, id, { requestId: "idem-1", code: "755224", lookAhead: 0 });
  assert.equal(retry.replayed, true);
  assert.equal(retry.result, "ACCEPTED");
  const state = svc.getVerifierState(db, id) as { nextCounter: string };
  assert.equal(state.nextCounter, "1", "重试不得再次消费");
  assert.throws(
    () => svc.verify(db, id, { requestId: "idem-1", code: "287082", lookAhead: 0 }),
    (e: unknown) => e instanceof HotpError && (e as HotpError).code === "REQUEST_CONFLICT"
  );
  assert.throws(
    () => svc.verify(db, id, { requestId: "idem-1", code: "755224", lookAhead: 3 }),
    (e: unknown) => e instanceof HotpError && (e as HotpError).code === "REQUEST_CONFLICT"
  );
});

test("并发：同一未消费计数器最多一条新验证成功", async () => {
  const db = memDb();
  const id = makeDevice(db);
  const results = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      Promise.resolve().then(() =>
        svc.verify(db, id, { requestId: `c-${i}`, code: "755224", lookAhead: 0 })
      )
    )
  );
  const accepted = results.filter((r) => r.result === "ACCEPTED");
  assert.equal(accepted.length, 1);
  assert.equal(results.filter((r) => r.result === "NO_MATCH").length, 7);
});

test("重启后保持 nextCounter 与幂等记录", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "hotp-test-"));
  try {
    const file = path.join(dir, "t.db");
    let db = openDatabase(file);
    const id = makeDevice(db);
    svc.verify(db, id, { requestId: "boot-1", code: "755224", lookAhead: 0 });
    db.close();
    db = openDatabase(file);
    const state = svc.getVerifierState(db, id) as { nextCounter: string };
    assert.equal(state.nextCounter, "1");
    const replay = svc.verify(db, id, { requestId: "boot-1", code: "755224", lookAhead: 0 });
    assert.equal(replay.replayed, true);
    assert.equal(replay.result, "ACCEPTED");
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("重置开启新轮次，旧记录可查", () => {
  const db = memDb();
  const id = makeDevice(db);
  svc.verify(db, id, { requestId: "pre", code: "755224", lookAhead: 0 });
  const reset = svc.resetDevice(db, id) as { round: number; previousRound: number };
  assert.equal(reset.previousRound, 1);
  assert.equal(reset.round, 2);
  const state = svc.getVerifierState(db, id) as { nextCounter: string; round: number };
  assert.equal(state.nextCounter, "0");
  assert.equal(state.round, 2);
  const audit = svc.listAudit(db, id) as { round: number; requestId: string }[];
  assert.ok(audit.some((a) => a.round === 1 && a.requestId === "pre"));
});

test("最大计数器成功后设备耗尽且不回绕", () => {
  const db = memDb();
  const id = makeDevice(db);
  db.prepare("UPDATE devices SET next_counter = ? WHERE id = ?").run(MAX_UINT64.toString(), id);
  const code = hotp(RFC_SECRET, MAX_UINT64, 6);
  const ok = svc.verify(db, id, { requestId: "max-1", code, lookAhead: 0 });
  assert.equal(ok.result, "ACCEPTED");
  assert.equal(ok.acceptedCounter, MAX_UINT64.toString());
  const after = svc.verify(db, id, { requestId: "max-2", code, lookAhead: 100 });
  assert.equal(after.result, "EXHAUSTED");
  const state = svc.getVerifierState(db, id) as { nextCounter: string; exhausted: boolean };
  assert.equal(state.nextCounter, MAX_UINT64.toString());
  assert.equal(state.exhausted, true);
});

test("密钥与参数校验", () => {
  const db = memDb();
  assert.throws(() => svc.createDevice(db, { secretHex: "abcd" }), HotpError); // 太短
  assert.throws(() => svc.createDevice(db, { secretHex: "zz".repeat(20) }), HotpError); // 非十六进制
  assert.throws(() => svc.createDevice(db, { digits: 7 }), HotpError);
  assert.throws(
    () => svc.verify(db, makeDevice(db), { requestId: "x", code: "755224", lookAhead: 101 }),
    HotpError
  );
});

test("列表与审计脱敏：不出现完整密钥与口令明文", () => {
  const db = memDb();
  const id = makeDevice(db);
  svc.verify(db, id, { requestId: "m1", code: "755224", lookAhead: 0 });
  const listJson = JSON.stringify(svc.listDevices(db));
  const auditJson = JSON.stringify(svc.listAudit(db, id));
  assert.ok(!listJson.includes(RFC_SECRET_HEX));
  assert.ok(!auditJson.includes(RFC_SECRET_HEX));
  assert.ok(!auditJson.includes("755224"));
});

test("HTTP API 端到端", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), "hotp-http-"));
  const { server, port, db } = await startServer(0, path.join(dir, "t.db"));
  try {
    const base = `http://127.0.0.1:${port}`;
    const created = (await (
      await fetch(`${base}/devices`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "api", secretHex: RFC_SECRET_HEX, digits: 6 }),
      })
    ).json()) as { id: string; secretHex: string };
    assert.equal(created.secretHex, RFC_SECRET_HEX); // 创建时一次性显示

    const tok = (await (
      await fetch(`${base}/devices/${created.id}/tokens`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ counter: "0" }),
      })
    ).json()) as { code: string };
    assert.equal(tok.code, "755224");

    const v = (await (
      await fetch(`${base}/devices/${created.id}/verifications`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ requestId: "http-1", code: tok.code, lookAhead: 0 }),
      })
    ).json()) as { result: string; newNext: string };
    assert.equal(v.result, "ACCEPTED");
    assert.equal(v.newNext, "1");

    const list = (await (await fetch(`${base}/devices`)).json()) as { secretHex?: string }[];
    assert.equal(list[0].secretHex, undefined, "列表不得包含完整密钥");
  } finally {
    server.close();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
