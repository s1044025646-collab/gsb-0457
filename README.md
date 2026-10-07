# HOTP 计数器口令教学服务（本地后端）

一个**仅用于本地教学**的 HOTP（RFC 4226）计数器口令生成与前瞻窗口核验后端。
使用 TypeScript + Node.js + SQLite（Node 内置 `node:sqlite`），只提供 HTTP API 与 CLI，
无 Docker / WSL / 付费服务 / 外部在线 API 依赖。

> **教学声明**：本项目使用教学级存储（密钥以十六进制明文存于本地 SQLite 文件），
> 不声称达到生产认证系统的密钥保护能力。不实现 TOTP、二维码、账户平台或短信服务，
> 不读取浏览器、系统账户或其他应用的凭据；全部样例使用专门生成的测试密钥。

## 环境要求

- Windows 本地，Node.js ≥ 22.5（使用了内置 `node:sqlite`，无需原生编译依赖）
- `npm install`（仅安装 TypeScript 与类型定义两个开发依赖）

## 快速开始

```powershell
npm install
npm run build     # 编译 TypeScript 到 dist/
npm test          # 构建并运行全部测试（node:test）
npm start         # 启动 HTTP API，默认监听 127.0.0.1 的空闲端口
npm run demo      # 端到端演示：RFC 4226 向量 + 前瞻窗口 + 重放拒绝
npm run cli -- help
```

端口配置：`npm start -- --port=8080` 或环境变量 `PORT`；缺省为 `0`（操作系统分配空闲端口）。
数据目录：默认 `./data/hotp.db`，可用环境变量 `HOTP_DB_PATH` 指定其他文件。

## 核心算法（src/hotp.ts）

- 计数器：`0 .. 2^64-1` 的无符号整数，以十进制字符串输入并用 **BigInt** 解析，
  编码为**恰好 8 字节大端**后作为 HMAC 消息（绝不使用十进制文本或小端字节）。
- 摘要：Node 内置 `crypto` 的 **HMAC-SHA1**。
- 动态截取：摘要最后一字节低 4 位为偏移，取 4 字节并屏蔽最高位得 31 位非负整数，
  对 `10^digits` 取余后补前导零（`digits` 为 6 或 8）。
- 密钥：严格十六进制输入，16–64 字节；不提供 Base32 解码。

RFC 4226 公开测试密钥 ASCII `12345678901234567890` 的十六进制为
`3132333435363738393031323334353637383930`，计数器 0/1/2 的六位口令为
`755224`、`287082`、`359152`（0–9 完整向量见测试与 `vectors` 命令）。

## 验证语义（src/service.ts）

- 在闭区间 `[nextCounter, nextCounter + lookAhead]` 内**从小到大**匹配，
  `lookAhead` 限 `0..100`，越过 `2^64-1` 的部分不检查。
- 命中后消费该计数器及之前跳过的范围：`nextCounter = 匹配值 + 1`；
  不同计数器口令可能碰撞，取窗口内**最小**匹配项，不因字符串曾出现而永久封禁。
- 匹配到 `2^64-1` 后设备标记 `exhausted`，**不回绕**到 0。
- 无匹配、口令含空格、非数字或位数错误均**不推进**计数器。
- 生成口令（`token`）是纯计算，**不改变**验证器状态；`nextCounter` 仅由成功验证推进。
- 设备创建后位数、密钥、规则版本固定；更换参数请新建设备。

## 事务、幂等与并发

- 每次验证的「读状态 → 匹配 → 更新 → 写审计」在单个 SQLite `BEGIN IMMEDIATE` 事务中完成，
  失败整体回滚，不留下半次推进；服务重启后 `nextCounter` 与幂等记录保持正确。
- 每个验证请求必须携带唯一 `requestId`：相同 ID 相同参数重试返回**原结果**（`replayed: true`）
  且不重复消费；相同 ID 不同口令或窗口参数返回 `REQUEST_CONFLICT`（HTTP 409）。
- 并发提交同一未消费计数器时，写事务串行化保证**最多一条**新验证成功。
- 审计记录包含轮次、请求 ID、结果码、接受计数器、前后 `nextCounter`、跳过数量与前瞻值；
  **不记录**完整密钥与待验证口令明文。设备列表只显示密钥指纹（SHA-256 前 16 位）。
- 完整密钥仅在 `create` 响应中显示一次。

## 重置演示

`reset` 针对明确的单个测试设备：开启**新验证轮次**（`round + 1`）、`nextCounter` 归零、
清除耗尽标记；旧轮次审计记录保留可查，不伪装成原轮次倒退。

## CLI 命令

```text
npm run cli -- create [--name=名称] [--secret=十六进制密钥] [--digits=6|8]
npm run cli -- list
npm run cli -- token <deviceId> <counter>
npm run cli -- status <deviceId>
npm run cli -- verify <deviceId> <requestId> <code> [--look-ahead=0..100]
npm run cli -- audit <deviceId>
npm run cli -- reset <deviceId>
npm run cli -- vectors <deviceId> [--from=0] [--count=10]
npm run cli -- serve [--port=0]
```

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/devices` | 创建设备 `{name?, secretHex?, digits?}`，完整密钥仅此响应返回 |
| GET | `/devices` | 设备列表（脱敏，仅指纹） |
| GET | `/devices/:id` | 验证器状态 |
| POST | `/devices/:id/tokens` | 纯计算口令 `{counter}`，不改变状态 |
| POST | `/devices/:id/verifications` | 提交验证 `{requestId, code, lookAhead?}`（幂等） |
| GET | `/devices/:id/audit` | 脱敏审计记录 |
| POST | `/devices/:id/reset` | 开启新验证轮次 |
| GET | `/devices/:id/test-vectors?from=0&count=10` | 导出可复算测试向量 |
| GET | `/health` | 健康检查 |

错误响应统一为 `{ "error": { "code", "message" } }`，主要错误码：
`INVALID_SECRET`、`INVALID_DIGITS`、`INVALID_COUNTER`、`COUNTER_OVERFLOW`、`INVALID_CODE_FORMAT`、
`INVALID_LOOKAHEAD`、`INVALID_REQUEST_ID`、`REQUEST_CONFLICT`、`DEVICE_NOT_FOUND`、`INVALID_JSON`。

## 测试覆盖（test/hotp.test.ts，19 个用例）

- RFC 4226 计数器 0–9 公开六位向量；HMAC-SHA1 中间摘要经**独立实现**（.NET HMACSHA1）交叉核验；
  反向构造（十进制文本 / 小端字节作为消息）应失败。
- 前导零补足、八位模式（与六位同源且低六位一致）、大于 2^53 的计数器（BigInt）。
- 前瞻窗口：窗口末端接受、窗口外拒绝、失败不推进、重放拒绝、耗尽不回绕。
- 请求幂等与冲突、并发下同一计数器最多一条成功、重启后状态与幂等记录保持。
- 重置开新轮次且旧记录可查、脱敏检查、HTTP 端到端。

## 已知限制

- 教学级密钥存储：密钥明文存于本地 SQLite 文件，无 KMS/SE/加密信封保护。
- 单进程服务；`node:sqlite` 为同步 API，靠单写事务保证一致性，未做横向扩展。
- 无认证/授权层，任何能访问端口与数据文件的本地用户都可操作，请勿用于真实账号。
