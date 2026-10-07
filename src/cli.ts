import { HotpService } from "./service.js";
import { Store, defaultDbPath } from "./db.js";
import { createApp } from "./server.js";
import { HotpError } from "./hotp.js";

const RFC_KEY_HEX = Buffer.from("12345678901234567890", "ascii").toString("hex");

function argValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
}

function print(x: unknown): void {
  console.log(JSON.stringify(x, null, 2));
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  const service = new HotpService(new Store(defaultDbPath()));

  switch (cmd) {
    case "create": {
      const r = service.createDevice({
        name: argValue(args, "name"),
        digits: argValue(args, "digits") ? Number(argValue(args, "digits")) : 6,
        keyHex: argValue(args, "key-hex") ?? RFC_KEY_HEX,
      });
      console.log("设备已创建。测试密钥仅在此显示一次，请妥善保存：");
      print(r);
      break;
    }
    case "list":
      print(service.listDevices());
      break;
    case "status":
      print(service.status(argValue(args, "device") ?? ""));
      break;
    case "generate":
      print(service.generate(argValue(args, "device") ?? "", argValue(args, "counter") ?? ""));
      break;
    case "verify":
      print(
        service.verify(argValue(args, "device") ?? "", {
          requestId: argValue(args, "request-id") ?? "",
          code: argValue(args, "code") ?? "",
          lookAhead: argValue(args, "look-ahead") !== undefined ? Number(argValue(args, "look-ahead")) : undefined,
        })
      );
      break;
    case "audit":
      print(service.audit(argValue(args, "device") ?? ""));
      break;
    case "reset":
      print(service.reset(argValue(args, "device") ?? ""));
      break;
    case "vectors":
      print(service.exportVectors(argValue(args, "device") ?? "", argValue(args, "from") ?? "0", argValue(args, "to") ?? "9"));
      break;
    case "serve": {
      const app = createApp(service);
      const port = argValue(args, "port") ? Number(argValue(args, "port")) : 0;
      app.listen(port, "127.0.0.1", () => {
        const addr = app.address();
        console.log(`HOTP 教学服务已启动: http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : port}`);
      });
      break;
    }
    case "demo": {
      console.log("=== RFC 4226 演示：测试密钥 12345678901234567890 (ASCII) ===");
      const dev = service.createDevice({ name: "rfc4226-demo", digits: 6, keyHex: RFC_KEY_HEX });
      console.log(`设备: ${dev.id}  密钥指纹: ${dev.keyFingerprint}`);
      console.log(`计数器 0/1/2 口令: ${service.generate(dev.id, "0").code} / ${service.generate(dev.id, "1").code} / ${service.generate(dev.id, "2").code}`);
      console.log("--- 以前瞻窗口 2 提交计数器 2 的口令 359152 ---");
      print(service.verify(dev.id, { requestId: "demo-1", code: "359152", lookAhead: 2 }));
      console.log("--- 状态（应推进到 3） ---");
      print(service.status(dev.id));
      console.log("--- 以前瞻 0 重放计数器 0 的口令 755224（应拒绝且不推进） ---");
      print(service.verify(dev.id, { requestId: "demo-2", code: "755224", lookAhead: 0 }));
      console.log("--- 相同请求 ID 重试 demo-1（幂等返回原结果） ---");
      print(service.verify(dev.id, { requestId: "demo-1", code: "359152", lookAhead: 2 }));
      break;
    }
    default:
      console.log(`用法: node src/cli.ts <命令> [参数]
命令:
  create   --name N --digits 6|8 --key-hex HEX   创建测试设备（密钥仅显示一次）
  list                                          列出设备（仅指纹）
  status   --device ID                          查看验证器状态
  generate --device ID --counter N              纯计算指定计数器口令
  verify   --device ID --request-id R --code C [--look-ahead N]
  audit    --device ID                          查看脱敏审计记录
  reset    --device ID                          重置演示（开启新轮次）
  vectors  --device ID --from A --to B          导出可复算测试向量
  serve    [--port N]                           启动 HTTP 服务（默认空闲端口）
  demo                                          RFC 4226 场景演示`);
  }
}

main().catch((err) => {
  if (err instanceof HotpError) {
    console.error(`错误 [${err.code}] ${err.message}`);
    process.exit(1);
  }
  throw err;
});
