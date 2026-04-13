import { describe, it, expect, afterEach } from "vitest";
import { ScanEventEmitter } from "../../src/dashboard/events.js";
import { startDashboard, type DashboardHandle } from "../../src/dashboard/server.js";
import WebSocket from "ws";

describe("DashboardServer", () => {
  let handle: DashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.close();
      handle = null;
    }
  });

  it("starts on the specified port and serves index.html", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });

    const res = await fetch(`http://localhost:${handle.port}/`);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("Sentinel Dashboard");
  });

  it("relays scan events to WebSocket clients", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });

    const ws = new WebSocket(`ws://localhost:${handle.port}/ws`);
    const messages: string[] = [];

    await new Promise<void>((resolve) => {
      ws.on("open", () => resolve());
    });

    ws.on("message", (data) => messages.push(data.toString()));

    emitter.emitEvent({ type: "scan:start", project: "test", timestamp: Date.now() });

    // Give the event loop a tick to deliver
    await new Promise((r) => setTimeout(r, 50));

    expect(messages).toHaveLength(1);
    const parsed = JSON.parse(messages[0]);
    expect(parsed.type).toBe("scan:start");
    expect(parsed.project).toBe("test");

    ws.close();
  });

  it("closes cleanly", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });
    const port = handle.port;

    await handle.close();
    handle = null;

    // Port should be released
    await expect(fetch(`http://localhost:${port}/`)).rejects.toThrow();
  });
});
