import { describe, it, expect, afterEach } from "vitest";
import { ScanEventEmitter } from "../../src/dashboard/events.js";
import { startDashboard, type DashboardHandle } from "../../src/dashboard/server.js";
import type { ScanEvent } from "../../src/dashboard/events.js";
import WebSocket from "ws";

describe("Dashboard integration", () => {
  let handle: DashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.close();
      handle = null;
    }
  });

  it("streams a full scan lifecycle to WebSocket client", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });

    const ws = new WebSocket(`ws://localhost:${handle.port}/ws`);
    const received: ScanEvent[] = [];

    await new Promise<void>((resolve) => ws.on("open", resolve));
    ws.on("message", (data) => received.push(JSON.parse(data.toString())));

    // Simulate a scan lifecycle
    emitter.emitEvent({ type: "scan:start", project: "/tmp/test-project", timestamp: Date.now() });
    emitter.emitEvent({ type: "layer:start", layer: "recon", timestamp: Date.now() });
    emitter.emitEvent({
      type: "recon:route",
      data: { path: "/", method: "GET", file: "src/app/page.tsx", isApi: false, hasAuthCheck: false },
    });
    emitter.emitEvent({
      type: "recon:endpoint",
      data: { path: "/api/users", method: "GET", file: "src/app/api/users/route.ts", hasValidation: true, hasAuthCheck: true, usesServiceRole: false },
    });
    emitter.emitEvent({ type: "layer:complete", layer: "recon", durationMs: 500, timestamp: Date.now() });
    emitter.emitEvent({ type: "layer:start", layer: "rules", timestamp: Date.now() });
    emitter.emitEvent({
      type: "finding",
      data: {
        id: "SEC-001",
        severity: "high",
        title: "Missing rate limiting",
        file: "src/app/api/users/route.ts",
        line: 15,
        domain: "api-security",
        layer: "rules",
        remediation: "Add rate limiting middleware",
      },
    });
    emitter.emitEvent({ type: "layer:complete", layer: "rules", durationMs: 200, timestamp: Date.now() });
    emitter.emitEvent({
      type: "scan:complete",
      summary: {
        routes: 1,
        endpoints: 1,
        dataModels: 0,
        externalServices: 0,
        findings: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        durationMs: 700,
      },
      timestamp: Date.now(),
    });

    // Allow delivery
    await new Promise((r) => setTimeout(r, 100));

    ws.close();

    // Verify the event sequence
    expect(received.length).toBeGreaterThanOrEqual(8);
    expect(received[0].type).toBe("scan:start");
    expect(received[1].type).toBe("layer:start");

    const routes = received.filter((e) => e.type === "recon:route");
    expect(routes).toHaveLength(1);

    const endpoints = received.filter((e) => e.type === "recon:endpoint");
    expect(endpoints).toHaveLength(1);

    const findings = received.filter((e) => e.type === "finding");
    expect(findings).toHaveLength(1);
    if (findings[0].type === "finding") {
      expect(findings[0].data.severity).toBe("high");
    }

    const complete = received.find((e) => e.type === "scan:complete");
    expect(complete).toBeDefined();
    if (complete?.type === "scan:complete") {
      expect(complete.summary.routes).toBe(1);
    }
  });

  it("serves the dashboard client at /", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });

    const res = await fetch(`http://localhost:${handle.port}/`);
    const html = await res.text();
    expect(html).toContain("Sentinel Dashboard");
    expect(html).toContain("graph-svg");
    expect(html).toContain("d3.v7.min.js");
  });
});
