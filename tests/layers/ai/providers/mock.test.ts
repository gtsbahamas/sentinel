import { describe, it, expect } from "vitest";
import { MockProvider } from "../../../../src/layers/ai/providers/mock.js";
import type { GenerateRequest } from "../../../../src/layers/ai/providers/base.js";

const req = (userPrompt: string): GenerateRequest => ({
  systemPrompt: "sys",
  projectSummary: "sum",
  userPrompt,
  toolDefinition: { name: "report_findings", description: "", schema: {} },
  maxInputTokens: 8000,
  maxOutputTokens: 2000,
});

describe("MockProvider", () => {
  it("dispatches by userPrompt key", async () => {
    const mock = new MockProvider({
      "/api/users/[id]": {
        rawFindings: [{ ruleId: "AI-IDOR-001" }],
        usage: { inputTokens: 1000, outputTokens: 100, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 },
        stopReason: "tool_use",
      },
    });
    const resp = await mock.generateFindings(req("/api/users/[id]"));
    expect(resp.rawFindings).toHaveLength(1);
    expect(resp.stopReason).toBe("tool_use");
    expect(resp.usage.inputTokens).toBe(1000);
  });

  it("fails loudly on unknown key", async () => {
    const mock = new MockProvider({});
    await expect(mock.generateFindings(req("/api/unknown"))).rejects.toThrow(/MockProvider.*unknown key/);
  });

  it("records call counts", async () => {
    const mock = new MockProvider({
      "a": { rawFindings: [], usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 }, stopReason: "tool_use" },
    });
    await mock.generateFindings(req("a"));
    await mock.generateFindings(req("a"));
    expect(mock.callCount).toBe(2);
  });

  it("returns zero-cost estimates (mock pricing is free)", () => {
    const mock = new MockProvider({});
    const est = mock.estimateTokens(req("anything"));
    expect(est.estimatedCostUsd).toBe(0);
    expect(est.inputTokens).toBeGreaterThan(0); // approximates length
  });

  it("can inject stopReason: error", async () => {
    const mock = new MockProvider({
      "bad": { rawFindings: [], usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 }, stopReason: "error", rawError: "simulated" },
    });
    const resp = await mock.generateFindings(req("bad"));
    expect(resp.stopReason).toBe("error");
    expect(resp.rawError).toBe("simulated");
  });
});
