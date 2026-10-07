import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { HotpService } from "./service.js";
import { Store, defaultDbPath } from "./db.js";
import { HotpError } from "./hotp.js";

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new HotpError("INVALID_JSON", "请求体不是合法 JSON");
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(json);
}

export function createApp(service: HotpService) {
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const parts = url.pathname.split("/").filter(Boolean);
      const method = req.method ?? "GET";
      const body = method === "POST" ? ((await readBody(req)) as Record<string, unknown>) : {};

      if (method === "GET" && url.pathname === "/health") {
        return send(res, 200, { ok: true });
      }
      if (method === "POST" && url.pathname === "/devices") {
        return send(res, 201, service.createDevice(body as never));
      }
      if (method === "GET" && url.pathname === "/devices") {
        return send(res, 200, service.listDevices());
      }
      if (parts[0] === "devices" && parts[1]) {
        const id = parts[1];
        if (method === "GET" && parts.length === 2) return send(res, 200, service.status(id));
        if (method === "POST" && parts[2] === "generate") {
          return send(res, 200, service.generate(id, String(body.counter ?? "")));
        }
        if (method === "POST" && parts[2] === "verify") {
          const result = service.verify(id, {
            requestId: String(body.requestId ?? ""),
            code: String(body.code ?? ""),
            lookAhead: body.lookAhead === undefined ? undefined : Number(body.lookAhead),
          });
          return send(res, result.matched ? 200 : 200, result);
        }
        if (method === "GET" && parts[2] === "audit") return send(res, 200, service.audit(id));
        if (method === "POST" && parts[2] === "reset") return send(res, 200, service.reset(id));
        if (method === "GET" && parts[2] === "vectors") {
          return send(res, 200, service.exportVectors(id, url.searchParams.get("from") ?? "0", url.searchParams.get("to") ?? "9"));
        }
      }
      return send(res, 404, { error: { code: "NOT_FOUND", message: "路由不存在" } });
    } catch (err) {
      if (err instanceof HotpError) {
        const status = err.code === "DEVICE_NOT_FOUND" ? 404 : err.code === "REQUEST_CONFLICT" ? 409 : 400;
        return send(res, status, { error: { code: err.code, message: err.message } });
      }
      return send(res, 500, { error: { code: "INTERNAL", message: String(err) } });
    }
  });
}

if (process.argv[1] && import.meta.url === new URL(`file:///${process.argv[1].replace(/\\/g, "/")}`).href) {
  const service = new HotpService(new Store(defaultDbPath()));
  const app = createApp(service);
  const portArg = process.env.PORT ? Number(process.env.PORT) : 0; // 默认选择空闲端口
  app.listen(portArg, "127.0.0.1", () => {
    const addr = app.address();
    const port = typeof addr === "object" && addr ? addr.port : portArg;
    console.log(`HOTP 教学服务已启动: http://127.0.0.1:${port}`);
  });
}
