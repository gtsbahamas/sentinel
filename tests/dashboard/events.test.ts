import { describe, it, expect, vi } from "vitest";
import { ScanEventEmitter } from "../../src/dashboard/events.js";
import type { ScanEvent } from "../../src/dashboard/events.js";

describe("ScanEventEmitter", () => {
  it("emits scan:start event with correct shape", () => {
    const emitter = new ScanEventEmitter();
    const handler = vi.fn();
    emitter.on("scan-event", handler);

    emitter.emitEvent({ type: "scan:start", project: "test-project", timestamp: Date.now() });

    expect(handler).toHaveBeenCalledOnce();
    const event: ScanEvent = handler.mock.calls[0][0];
    expect(event.type).toBe("scan:start");
    expect(event.project).toBe("test-project");
  });

  it("emits recon:route event with route data", () => {
    const emitter = new ScanEventEmitter();
    const handler = vi.fn();
    emitter.on("scan-event", handler);

    emitter.emitEvent({
      type: "recon:route",
      data: { path: "/api/users", method: "GET", file: "src/app/api/users/route.ts", isApi: true, hasAuthCheck: true },
    });

    const event = handler.mock.calls[0][0] as ScanEvent;
    expect(event.type).toBe("recon:route");
    if (event.type === "recon:route") {
      expect(event.data.path).toBe("/api/users");
      expect(event.data.isApi).toBe(true);
    }
  });

  it("emits finding event", () => {
    const emitter = new ScanEventEmitter();
    const handler = vi.fn();
    emitter.on("scan-event", handler);

    emitter.emitEvent({
      type: "finding",
      data: {
        id: "RULE-001",
        severity: "high",
        title: "Exposed API key",
        file: "src/config.ts",
        line: 42,
        domain: "secrets-exposure",
        layer: "rules",
      },
    });

    const event = handler.mock.calls[0][0] as ScanEvent;
    expect(event.type).toBe("finding");
    if (event.type === "finding") {
      expect(event.data.severity).toBe("high");
    }
  });

  it("emits layer lifecycle events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("scan-event", (e) => events.push(e));

    emitter.emitEvent({ type: "layer:start", layer: "recon", timestamp: Date.now() });
    emitter.emitEvent({ type: "layer:complete", layer: "recon", durationMs: 1200, timestamp: Date.now() });

    expect(events).toHaveLength(2);
    expect(events[0].type).toBe("layer:start");
    expect(events[1].type).toBe("layer:complete");
  });

  it("emits scan:complete with summary", () => {
    const emitter = new ScanEventEmitter();
    const handler = vi.fn();
    emitter.on("scan-event", handler);

    emitter.emitEvent({
      type: "scan:complete",
      summary: {
        routes: 12,
        endpoints: 8,
        dataModels: 3,
        externalServices: 2,
        findings: { critical: 1, high: 3, medium: 5, low: 2, info: 0 },
        durationMs: 4500,
      },
      timestamp: Date.now(),
    });

    const event = handler.mock.calls[0][0] as ScanEvent;
    expect(event.type).toBe("scan:complete");
    if (event.type === "scan:complete") {
      expect(event.summary.routes).toBe(12);
      expect(event.summary.findings.critical).toBe(1);
    }
  });
});
