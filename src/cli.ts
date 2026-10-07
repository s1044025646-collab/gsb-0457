import { openDatabase } from "./db";
import { HotpError } from "./hotp";
import * as svc from "./service";

function parseArgs(argv: string[]): { cmd: string; positional: string[]; opts: Record<string, string> } {
  const [cmd = "help", ...rest] = argv;
  const positional: string[] = [];
  const opts: Record<string, string> = {};
  for (const a of rest) {
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq > 2) opts[a.slice(2, eq)] = a.slice(eq + 1);
      else opts[a.slice(2)] = "true";
    } else positional.push(a);
  }
  return { cmd, positional, opts };
}

const HELP_LINES = [
  "HOTP 教学服务 CLI（仅本地教学用途）",
  "用法: npm run cli -- <命令> [参数] [--选项=值]",
  "",
  "命令:",
  "  create [--name=名称] [--secret=十六进制密钥] [--digits=6|8]   创建测试设备（完整密钥仅此显示一次）",
  "  list                                                        列出设备（脱敏，仅指纹）",
  "  token <deviceId> <counter>                                  纯计算生成口令，不改变状态",
  "  status <deviceId>                                           查看验证器状态",
  "  verify <deviceId> <requestId> <code> [--look-ahead=0..100]  提交验证（幂等）",
  "  audit <deviceId>                                            查看脱敏审计记录",
  "  reset <deviceId>                                            重置演示：开启新验证轮次",
  "  vectors <deviceId> [--from=0] [--count=10]                  导出可复算测试向量",
  "  serve [--port=0]                                            启动 HTTP API（默认空闲端口）",
  "环境变量: HOTP_DB_PATH 指定数据库文件，默认 ./data/hotp.db",
];
const HELP = HELP_LINES.join("\n");

function print(value: unknown): void {
  console.log(typeof value === "string" ? value : JSON.stringify(value, null, 2));
}

async function main(): Promise<void> {
  const { cmd, positional, opts } = parseArgs(process.argv.slice(2));
  if (cmd === "help" || cmd === "--help") return print(HELP);
  if (cmd === "serve") {
    const { startServer } = await import("./server.js");
    const port = opts.port ? Number(opts.port) : Number(process.env.PORT ?? 0);
    const { port: actual } = await startServer(port);
    return print("HOTP 教学服务已启动: http://127.0.0.1:" + actual);
  }

  const db = openDatabase();
  switch (cmd) {
    case "create":
      return print(
        svc.createDevice(db, {
          name: opts.name,
          secretHex: opts.secret,
          digits: opts.digits ? Number(opts.digits) : undefined,
        })
      );
    case "list":
      return print(svc.listDevices(db));
    case "token":
      return print(svc.generateToken(db, positional[0], positional[1] ?? ""));
    case "status":
      return print(svc.getVerifierState(db, positional[0]));
    case "verify":
      return print(
        svc.verify(db, positional[0], {
          requestId: positional[1],
          code: positional[2],
          lookAhead: opts["look-ahead"] !== undefined ? Number(opts["look-ahead"]) : undefined,
        })
      );
    case "audit":
      return print(svc.listAudit(db, positional[0]));
    case "reset":
      return print(svc.resetDevice(db, positional[0]));
    case "vectors":
      return print(svc.exportTestVectors(db, positional[0], opts.from ?? "0", Number(opts.count ?? "10")));
    default:
      print("未知命令: " + cmd + "\n\n" + HELP);
      process.exitCode = 1;
  }
}

main().catch((err) => {
  if (err instanceof HotpError) {
    console.error("错误 [" + err.code + "]: " + err.message);
  } else {
    console.error(err);
  }
  process.exitCode = 1;
});
