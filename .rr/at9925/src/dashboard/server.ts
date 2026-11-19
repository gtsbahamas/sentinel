import express from "express";
import { WebSocketServer } from "ws";
import { createServer } from "node:http";
import open from "open";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { ScanEventEmitter } from "./events.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface DashboardOptions {
  port?: number;        // default: 4400
  openBrowser?: boolean; // default: true
}

export interface DashboardHandle {
  port: number;
  close: () => Promise<void>;
}

export async function startDashboard(
  emitter: ScanEventEmitter,
  options?: DashboardOptions,
): Promise<DashboardHandle> {
  const port = options?.port ?? 4400;
  const app = express();
  const server = createServer(app);
  const wss = new WebSocketServer({ server, path: "/ws" });

  app.use(express.static(join(__dirname, "client")));

  // Buffer all events so late-connecting clients get full replay
  const eventBuffer: string[] = [];

  emitter.on("scan-event", (event) => {
    const payload = JSON.stringify(event);
    eventBuffer.push(payload);
    for (const client of wss.clients) {
      if (client.readyState === 1) {
        client.send(payload);
      }
    }
  });

  // Replay buffered events to newly connected clients
  wss.on("connection", (ws) => {
    for (const payload of eventBuffer) {
      ws.send(payload);
    }
  });

  const actualPort = await new Promise<number>((resolve, reject) => {
    server.on("error", reject);
    server.listen(port, () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        resolve(addr.port);
      } else {
        resolve(port);
      }
    });
  });

  if (options?.openBrowser !== false) {
    await open(`http://localhost:${actualPort}`);
  }

  return {
    port: actualPort,
    close: () =>
      new Promise<void>((resolve, reject) => {
        for (const client of wss.clients) {
          client.terminate();
        }
        wss.close(() => {
          server.close((err) => (err ? reject(err) : resolve()));
        });
      }),
  };
}
