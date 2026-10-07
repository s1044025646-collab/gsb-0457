# HOTP 教学服务（RFC 4226）

本项目是**本地教学用**的 HOTP 计数器口令后端：创建虚构测试设备，按共享测试密钥与整数计数器生成六位或八位口令，并模拟服务端前瞻窗口验证与计数器推进。仅提供 HTTP API 与 CLI，无 UI。

- 算法：RFC 4226，HMAC-SHA1（使用 Node 内置 `crypto`）
- 存储：SQLite（Node 内置 `node:sqlite`，零原生依赖）
- 平台：Windows 本地运行，无需 Docker / WSL / 外部服务
- **明确不实现**：TOTP、二维码扫码、账户登录平台、短信服务、Base32 密钥

> 教学声明：本项目使用教学级存储（密钥以十六进制明文存于本地 SQLite，仅演示协议与状态机），**不声称达到生产认证系统的密钥保护能力**。所有样例均使用专门生成的测试密钥，不读取浏览器、系统账户或其他应用的凭据。

## 核心实现要点

- 计数器：`0 .. 2^64-1` 的无符号整数，十进制字符串输入，使用 `BigInt` 处理；编码为**恰好 8 字节大端**后作为 HMAC 消息（绝不用十进制文本或小端字节）。
- 动态截取：摘要最后一字节低 4 位为偏移，取 4 字节并屏蔽最高位得 31 位非负数，对 `10^digits` 取余并补足前导零。
- 密钥：严格十六进制输入，限定 16–64 字节；仅在 `create` 响应中明文显示一次，列表/状态/审计只给 SHA-256 指纹（前 16 位 hex）。
- 设备创建后位数、密钥、规则版本固定；更换参数请新建设备。
- `generate` 为纯计算，不改变验证器状态；`nextCounter` 只能由成功验证推进。
- 验证区间：闭区间 `[nextCounter, nextCounter + lookAhead]`，从小到大匹配（窗口内取最小匹配项，不因口令碰撞永久封禁）；`lookAhead ∈ [0, 100]`；越过 `2^64-1` 的部分不检查。
- 匹配成功：消费该计数器及此前跳过范围，`nextCounter = 匹配值 + 1`；匹配到 `2^64-1` 后设备标记耗尽，**不回绕到 0**。
- 无匹配、口令位数错误、含空格或非数字：一律不推进。
- 事务与幂等：验证 + 状态更新 + 幂等记录在同一 SQLite 事务（`BEGIN IMMEDIATE`）中完成；请求带唯一 `requestId`，相同请求重试返回原结果（`replay: true`）不重复消费；同一 ID 参数不同返回 `409 REQUEST_CONFLICT`；并发提交同一未私下消费计数器最多一条成功。
- 审计：记录接受的计数器、前后 `nextCounter`、跳过数量、结果码；**不记录**完整密钥与提交的口令。
- 重置演示：`reset` 开启新验证轮次（`round + 1`），旧轮次审计记录保留可查，不伪装成原轮次倒退。

## 环境要求

- Node.js >= 22.5（使用内置 `node:sqlite`；开发使用 Node 25 验证）
- 仅开发依赖：`typescript`、`@types/node`

## 快速开始

```powershell
npm install
npm run build     # 编译 TypeScript 到 dist/
npm test          # 运行全部测试（16 个）
npm start         # 启动 HTTP 服务（默认选择空闲端口，PORT=8080 可指定）
npm run demo      # RFC 4226 场景演示（前瞻 2 接受计数器 2 -> 推进到 3 -> 前瞻 0 重放计数器 0 被拒）
```

数据目录默认为项目内 `data/`（可用环境变量 `HOTP_DATA_DIR` 覆盖），重启后 `nextCounter` 与幂等记录保持。

## CLI 命令

```powershell
node dist/src/cli.js create --name demo --digits 6 --key-hex 3132333435363738393031323334353637383930
node dist/src/cli.js list
node dist/src/cli.js status --device <ID>
node dist/src/cli.js generate --device <ID> --counter 0
node dist/src/cli.js verify --device <ID> --request-id r1 --code 755224 --look-ahead 2
node dist/src/cli.js audit --device <ID>
node dist/src/cli.js reset --device <ID>
node dist/src/cli.js vectors --device <ID> --from 0 --to 9
node dist/src/cli.js serve --port 8080
node dist/src/cli.js demo
```

`create` 不传 `--key-hex` 时使用 RFC 4226 测试密钥（ASCII `12345678901234567890` 的十六进制）。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/devices` | 创建测试设备 `{name?, digits?, keyHex}`，密钥仅此一次明文返回 |
| GET | `/devices` | 设备列表（仅指纹） |
| GET | `/devices/:id` | 验证器状态（nextCounter、round、exhausted） |
| POST | `/devices/:id/generate` | 纯计算 `{counter}` 的口令，不改变状态 |
| POST | `/devices/:id/verify` | 提交验证 `{requestId, code, lookAhead?}` |
| GET | `/devices/:id/audit` | 脱敏审计记录 |
| POST | `/devices/:id/reset` | 重置演示（开启新轮次） |
| GET | `/devices/:id/vectors?from=0&to=9` | 导出可复算测试向量（含测试密钥） |
| GET | `/health` | 健康检查 |

## 错误码

`INVALID_DIGITS` `INVALID_KEY_HEX` `INVALID_COUNTER` `INVALID_LOOK_AHEAD` `INVALID_REQUEST_ID` `INVALID_CODE_FORMAT` `INVALID_JSON` `INVALID_RANGE` `DEVICE_NOT_FOUND`(404) `REQUEST_CONFLICT`(409) `DEVICE_EXHAUSTED` `NO_MATCH` `MATCH`

## 测试向量（RFC 4226 附录 D，六位）

密钥为 ASCII `12345678901234567890`（hex `3132333435363738393031323334353637383930`）：

| 计数器 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 口令 | 755224 | 287082 | 359152 | 969429 | 338314 | 254676 | 287922 | 162583 | 399871 | 520489 |

测试覆盖：RFC 公开向量 0–9、独立 8 字节大端编码交叉核验（非本项目生成器自证）、前导零补足、八位模式、大于 2^53 的计数器、窗口末端匹配、失败/非法格式不推进、请求幂等与冲突、并发同一计数器最多一条成功、重启后状态与幂等保持、uint64 最大值耗尽不回绕、重置新轮次、脱敏检查。

## 已知限制

- 教学级密钥存储（明文 hex 存于本地 SQLite），无密钥派生/加密/访问控制。
- 单进程服务；`node:sqlite` 为 Node 实验性特性（启动时有 ExperimentalWarning）。
- 审计记录包含接受的计数器编号，属教学演示所需，生产系统应进一步最小化。
