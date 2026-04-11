import { describe, it, expect, vi, beforeEach } from "vitest";
import { OpenAIProvider, OPENAI_PRICING } from "../../../../src/layers/ai/providers/openai.js";
import type { GenerateRequest } from "../../../../src/layers/ai/providers/base.js";

const req: GenerateRequest = {
  systemPrompt: "system",
  projectSummary: "summary",
  userPrompt: "prompt",
  toolDefinition: { name: "report_findings", description: "desc", schema: { type: "object", properties: { findings: { type: "array" } }, required: ["findings"] } },
  maxInputTokens: 8000,
  maxOutputTokens: 2000,
};

const successResponse = {
  choices: [
    {
      message: {
        content: JSON.stringify({ findings: [{ ruleId: "AI-Y-002" }] }),
      },
      finish_reason: "stop",
    },
  ],
  usage: {
    prompt_tokens: 1200,
    completion_tokens: 150,
    prompt_tokens_details: { cached_tokens: 800 },
  },
};

describe("OpenAIProvider", () => {
  let fakeSdk: { chat: { completions: { create: ReturnType<typeof vi.fn> } } };
  let provider: OpenAIProvider;

  beforeEach(() => {
    fakeSdk = { chat: { completions: { create: vi.fn().mockResolvedValue(successResponse) } } };
    provider = new OpenAIProvider("gpt-5", fakeSdk as never);
  });

  it("sends response_format json_schema strict with findings schema", async () => {
    await provider.generateFindings(req);
    const args = fakeSdk.chat.completions.create.mock.calls[0][0];
    expect(args.model).toBe("gpt-5");
    expect(args.response_format.type).toBe("json_schema");
    expect(args.response_format.json_schema.strict).toBe(true);
    expect(args.response_format.json_schema.schema).toEqual(req.toolDefinition.schema);
  });

  it("parses JSON content into rawFindings", async () => {
    const resp = await provider.generateFindings(req);
    expect(resp.rawFindings).toEqual([{ ruleId: "AI-Y-002" }]);
    expect(resp.stopReason).toBe("end_turn");
  });

  it("tracks cached_tokens from usage.prompt_tokens_details", async () => {
    const resp = await provider.generateFindings(req);
    expect(resp.usage.inputTokens).toBe(1200);
    expect(resp.usage.cacheReadTokens).toBe(800);
    expect(resp.usage.outputTokens).toBe(150);
  });

  it("returns error stopReason on SDK throw", async () => {
    fakeSdk.chat.completions.create.mockRejectedValueOnce(new Error("429"));
    const resp = await provider.generateFindings(req);
    expect(resp.stopReason).toBe("error");
    expect(resp.rawError).toContain("429");
  });

  it("returns error stopReason on malformed JSON content", async () => {
    fakeSdk.chat.completions.create.mockResolvedValueOnce({
      choices: [{ message: { content: "not json" }, finish_reason: "stop" }],
      usage: { prompt_tokens: 10, completion_tokens: 5, prompt_tokens_details: { cached_tokens: 0 } },
    });
    const resp = await provider.generateFindings(req);
    expect(resp.stopReason).toBe("error");
  });

  it("exports pricing for default model", () => {
    expect(OPENAI_PRICING["gpt-5"]).toBeDefined();
  });
});
