import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { AddressInfo } from "node:net";
import { openDatabase } from "./db";
import { HotpError } from "./hotp";
import * as svc from "./service";

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8").trim();
  if (!text) return {};
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new HotpError("INVALID_JSON", "请求体不是合法 JSON");
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body, null, 2);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(json);
}

export function startServer(port: number = Number(process.env.PORT ?? 0), dbPath?: string) {
  const db = openDatabase(dbPath);
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const parts = url.pathname.split("/").filter(Boolean);
      const method = req.method ?? "GET";

      if (method === "GET" && url.pathname === "/health") {
        return send(res, 200, { ok: true });
      }
      if (method === "POST" && url.pathname === "/devices") {
        return send(res, 201, svc.createDevice(db, await readBody(req)));
      }
      if (method === "GET" && url.pathname === "/devices") {
        return send(res, 200, svc.listDevices(db));
      }
      if (parts[0] === "devices" && parts.length >= 2) {
        const id = decodeURIComponent(parts[1]);
        const sub = parts[2];
        if (method === "GET" && parts.length === 2) {
          return send(res, 200, svc.getVerifierState(db, id));
        }
        if (method === "POST" && sub === "tokens") {
          const body = await readBody(req);
          return send(res, 200, svc.generateToken(db, id, String(body.counter ?? "")));
        }
        if (method === "POST" && sub === "verifications") {
          return send(res, 200, svc.verify(db, id, await readBody(req)));
        }
        if (method === "GET" && sub === "audit") {
          return send(res, 200, svc.listAudit(db, id));
        }
        if (method === "POST" && sub === "reset") {
          return send(res, 200, svc.resetDevice(db, id));
        }
        if (method === "GET" && sub === "test-vectors") {
          const from = url.searchParams.get("from") ?? "0";
          const count = Number(url.searchParams.get("count") ?? "10");
          return send(res, 200, svc.exportTestVectors(db, id, from, count));
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
  return new Promise<{ server: typeof server; port: number; db: typeof db }>((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const actual = (server.address() as AddressInfo).port;
      resolve({ server, port: actual, db });
    });
  });
}

if (require.main === module) {
  const portArg = process.argv.find((a) => a.startsWith("--port="));
  const port = portArg ? Number(portArg.split("=")[1]) : Number(process.env.PORT ?? 0);
  startServer(port).then(({ port }) => {
    console.log(`HOTP 教学服务已启动: http://127.0.0.1:${port}`);
  });
}
