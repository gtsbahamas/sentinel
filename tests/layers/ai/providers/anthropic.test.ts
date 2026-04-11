import { describe, it, expect, vi, beforeEach } from "vitest";
import { AnthropicProvider, ANTHROPIC_PRICING } from "../../../../src/layers/ai/providers/anthropic.js";
import type { GenerateRequest } from "../../../../src/layers/ai/providers/base.js";

const fakeReq: GenerateRequest = {
  systemPrompt: "You are a security analyzer.",
  projectSummary: "PROJECT: demo\nSTACK: nextjs-supabase",
  userPrompt: "ENDPOINT: GET /api/foo\n\nCode here.",
  toolDefinition: {
    name: "report_findings",
    description: "desc",
    schema: { type: "object", properties: { findings: { type: "array" } }, required: ["findings"] },
  },
  maxInputTokens: 8000,
  maxOutputTokens: 2000,
};

const successResponse = {
  content: [
    {
      type: "tool_use",
      name: "report_findings",
      input: { findings: [{ ruleId: "AI-X-001" }] },
    },
  ],
  stop_reason: "tool_use",
  usage: {
    input_tokens: 1000,
    output_tokens: 100,
    cache_creation_input_tokens: 500,
    cache_read_input_tokens: 400,
  },
};

describe("AnthropicProvider", () => {
  let fakeSdk: { messages: { create: ReturnType<typeof vi.fn> } };
  let provider: AnthropicProvider;

  beforeEach(() => {
    fakeSdk = { messages: { create: vi.fn().mockResolvedValue(successResponse) } };
    provider = new AnthropicProvider("claude-sonnet-4-6", fakeSdk as never);
  });

  it("sends projectSummary with cache_control and forces the tool call", async () => {
    await provider.generateFindings(fakeReq);
    const call = fakeSdk.messages.create.mock.calls[0][0];
    expect(call.model).toBe("claude-sonnet-4-6");
    expect(Array.isArray(call.system)).toBe(true);
    const cachedBlock = call.system.find((b: { text: string; cache_control?: unknown }) => b.text === fakeReq.projectSummary);
    expect(cachedBlock).toBeDefined();
    expect(cachedBlock.cache_control).toEqual({ type: "ephemeral" });
    expect(call.tool_choice).toEqual({ type: "tool", name: "report_findings" });
    expect(call.tools[0].name).toBe("report_findings");
  });

  it("extracts rawFindings from tool_use content", async () => {
    const resp = await provider.generateFindings(fakeReq);
    expect(resp.rawFindings).toEqual([{ ruleId: "AI-X-001" }]);
    expect(resp.stopReason).toBe("tool_use");
  });

  it("tracks cache tokens in returned usage", async () => {
    const resp = await provider.generateFindings(fakeReq);
    expect(resp.usage.inputTokens).toBe(1000);
    expect(resp.usage.outputTokens).toBe(100);
    expect(resp.usage.cacheWriteTokens).toBe(500);
    expect(resp.usage.cacheReadTokens).toBe(400);
    expect(resp.usage.estimatedCostUsd).toBeGreaterThan(0);
  });

  it("returns stopReason: error on SDK throw", async () => {
    fakeSdk.messages.create.mockRejectedValueOnce(new Error("boom"));
    const resp = await provider.generateFindings(fakeReq);
    expect(resp.stopReason).toBe("error");
    expect(resp.rawError).toContain("boom");
  });

  it("estimateTokens uses ~4 chars per token heuristic", () => {
    const est = provider.estimateTokens(fakeReq);
    expect(est.inputTokens).toBeGreaterThan(0);
    expect(est.estimatedCostUsd).toBeGreaterThan(0);
  });

  it("pricing is defined for the default model", () => {
    expect(ANTHROPIC_PRICING["claude-sonnet-4-6"]).toBeDefined();
    expect(ANTHROPIC_PRICING["claude-sonnet-4-6"].inputPerMTokUsd).toBeGreaterThan(0);
  });
});
