import { describe, it, expect } from "vitest";
import { ProbeCleanupRegistry } from "../../../src/layers/probe/cleanup-registry.js";

describe("ProbeCleanupRegistry", () => {
  it("executes obligations in LIFO order", async () => {
    const registry = new ProbeCleanupRegistry();
    const order: string[] = [];

    registry.register({ description: "first", severity: "blocking", cleanup: async () => { order.push("first"); } });
    registry.register({ description: "second", severity: "blocking", cleanup: async () => { order.push("second"); } });
    registry.register({ description: "third", severity: "blocking", cleanup: async () => { order.push("third"); } });

    expect(registry.pendingCount()).toBe(3);

    const result = await registry.executeAll();
    expect(result.executed).toBe(3);
    expect(result.failed).toBe(0);
    expect(order).toEqual(["third", "second", "first"]);
  });

  it("reports blocking failures", async () => {
    const registry = new ProbeCleanupRegistry();

    registry.register({ description: "good", severity: "blocking", cleanup: async () => {} });
    registry.register({ description: "bad", severity: "blocking", cleanup: async () => { throw new Error("cleanup failed"); } });

    const result = await registry.executeAll();
    expect(result.executed).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.failures[0].severity).toBe("blocking");
    expect(result.failures[0].error).toContain("cleanup failed");
  });

  it("reports best-effort failures without blocking", async () => {
    const registry = new ProbeCleanupRegistry();

    registry.register({ description: "optional", severity: "best-effort", cleanup: async () => { throw new Error("minor fail"); } });

    const result = await registry.executeAll();
    expect(result.failed).toBe(1);
    expect(result.failures[0].severity).toBe("best-effort");
  });

  it("returns empty result on second executeAll call", async () => {
    const registry = new ProbeCleanupRegistry();
    registry.register({ description: "once", severity: "blocking", cleanup: async () => {} });

    await registry.executeAll();
    const second = await registry.executeAll();
    expect(second.executed).toBe(0);
  });

  it("rejects registration after executeAll", async () => {
    const registry = new ProbeCleanupRegistry();
    await registry.executeAll();

    expect(() =>
      registry.register({ description: "late", severity: "blocking", cleanup: async () => {} }),
    ).toThrow("Cannot register obligations after cleanup has run");
  });
});
