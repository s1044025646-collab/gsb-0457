// 演示脚本：RFC 4226 测试密钥 + 前瞻窗口验证流程（使用独立演示数据库，不污染正式数据）
const path = require("node:path");
const { mkdtempSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { openDatabase } = require("../dist/src/db");
const svc = require("../dist/src/service");

const RFC_SECRET_HEX = "3132333435363738393031323334353637383930"; // ASCII "12345678901234567890"

const dir = mkdtempSync(path.join(tmpdir(), "hotp-demo-"));
const db = openDatabase(path.join(dir, "demo.db"));

const show = (title, v) => console.log(`\n== ${title} ==\n` + JSON.stringify(v, null, 2));

const device = svc.createDevice(db, { name: "rfc4226-demo", secretHex: RFC_SECRET_HEX, digits: 6 });
show("1. 创建测试设备（完整密钥仅此显示一次）", device);

show("2. 导出计数器 0..9 测试向量（应含 755224/287082/359152 ...）",
  svc.exportTestVectors(db, device.id, "0", 10));

show("3. 前瞻 2 提交计数器 2 的口令 359152 → 接受并推进到 3",
  svc.verify(db, device.id, { requestId: "demo-accept", code: "359152", lookAhead: 2 }));

show("4. 前瞻 0 重放已消费的计数器 0 口令 755224 → 拒绝且不推进",
  svc.verify(db, device.id, { requestId: "demo-replay", code: "755224", lookAhead: 0 }));

show("5. 相同请求 ID 重试 → 返回原结果（replayed）",
  svc.verify(db, device.id, { requestId: "demo-accept", code: "359152", lookAhead: 2 }));

show("6. 验证器状态", svc.getVerifierState(db, device.id));
show("7. 脱敏审计记录", svc.listAudit(db, device.id));

db.close();
rmSync(dir, { recursive: true, force: true });
console.log("\n演示完成（临时数据库已清理）。");
