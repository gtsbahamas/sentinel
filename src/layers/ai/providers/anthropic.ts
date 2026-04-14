import type { AIProvider, GenerateRequest, GenerateResponse } from "./base.js";
import type { ProviderPricing, TokenEstimate } from "../budget.js";

// Pricing per 1M tokens. Update these when Anthropic changes rates.
// Cache write is ~125% of input, cache read is ~10% of input (Anthropic policy 2026).
export const ANTHROPIC_PRICING: Record<string, ProviderPricing> = {
  "claude-sonnet-4-6": { inputPerMTokUsd: 3, outputPerMTokUsd: 15, cacheReadPerMTokUsd: 0.3, cacheWritePerMTokUsd: 3.75 },
  "claude-haiku-4-5": { inputPerMTokUsd: 1, outputPerMTokUsd: 5, cacheReadPerMTokUsd: 0.1, cacheWritePerMTokUsd: 1.25 },
};

interface MessagesCreateArgs {
  model: string;
  max_tokens: number;
  system: Array<{ type: "text"; text: string; cache_control?: { type: "ephemeral" } }>;
  messages: Array<{ role: "user"; content: string }>;
  tools: Array<{ name: string; description: string; input_schema: object }>;
  tool_choice: { type: "tool"; name: string };
}

interface MessagesCreateResponse {
  content: Array<{ type: string; name?: string; input?: unknown }>;
  stop_reason: "end_turn" | "tool_use" | "max_tokens" | string;
  usage: {
    input_tokens: number;
    output_tokens: number;
    cache_creation_input_tokens?: number;
    cache_read_input_tokens?: number;
  };
}

interface AnthropicLike {
  messages: { create: (args: MessagesCreateArgs) => Promise<MessagesCreateResponse> };
}

const CHARS_PER_TOKEN = 4;

export class AnthropicProvider implements AIProvider {
  readonly name = "anthropic" as const;
  private readonly pricing: ProviderPricing;

  constructor(
    private readonly model: string,
    private readonly client: AnthropicLike,
  ) {
    this.pricing = ANTHROPIC_PRICING[model] ?? ANTHROPIC_PRICING["claude-sonnet-4-6"];
  }

  async generateFindings(request: GenerateRequest): Promise<GenerateResponse> {
    try {
      // Only emit a cached projectSummary block when it actually has content.
      // The verification pass does not use projectSummary (file context lives
      // in the user prompt), and Anthropic rejects cache_control on empty
      // text blocks: "system.1: cache_control cannot be set for empty text blocks".
      const systemBlocks: Array<{ type: "text"; text: string; cache_control?: { type: "ephemeral" } }> = [
        { type: "text", text: request.systemPrompt },
      ];
      if (request.projectSummary.length > 0) {
        systemBlocks.push({
          type: "text",
          text: request.projectSummary,
          cache_control: { type: "ephemeral" },
        });
      }

      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: request.maxOutputTokens,
        system: systemBlocks,
        messages: [{ role: "user", content: request.userPrompt }],
        tools: [
          {
            name: request.toolDefinition.name,
            description: request.toolDefinition.description,
            input_schema: request.toolDefinition.schema,
          },
        ],
        tool_choice: { type: "tool", name: request.toolDefinition.name },
      });

      const inputTokens = response.usage.input_tokens;
      const outputTokens = response.usage.output_tokens;
      const cacheWrite = response.usage.cache_creation_input_tokens ?? 0;
      const cacheRead = response.usage.cache_read_input_tokens ?? 0;

      // Tool-aware extraction: each known tool has its own top-level array key.
      // report_findings       → input.findings
      // report_project_risks  → input.projectRisks
      // report_verdicts       → input.verdicts
      const extractionKey = ((): string => {
        if (request.toolDefinition.name === "report_verdicts") return "verdicts";
        if (request.toolDefinition.name === "report_project_risks") return "projectRisks";
        return "findings";
      })();

      const rawFindings: unknown[] = [];
      for (const block of response.content) {
        if (block.type === "tool_use" && block.name === request.toolDefinition.name && block.input) {
          const input = block.input as Record<string, unknown>;
          const arr = input[extractionKey];
          if (Array.isArray(arr)) rawFindings.push(...arr);
        }
      }

      const stopReason =
        response.stop_reason === "tool_use" || response.stop_reason === "end_turn" || response.stop_reason === "max_tokens"
          ? response.stop_reason
          : "error";

      return {
        rawFindings,
        stopReason,
        usage: {
          inputTokens,
          outputTokens,
          cacheReadTokens: cacheRead,
          cacheWriteTokens: cacheWrite,
          estimatedCostUsd: this.computeCost(inputTokens, outputTokens, cacheRead, cacheWrite),
        },
      };
    } catch (err) {
      return {
        rawFindings: [],
        stopReason: "error",
        usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 },
        rawError: err instanceof Error ? err.message : String(err),
      };
    }
  }

  estimateTokens(request: GenerateRequest): TokenEstimate {
    const inputTokens = Math.ceil(
      (request.systemPrompt.length + request.projectSummary.length + request.userPrompt.length) / CHARS_PER_TOKEN,
    );
    // Realistic baseline from live smoke tests: Anthropic averages ~1000-1500
    // output tokens per endpoint. Use 1500 (upper band) capped at maxOutputTokens.
    // Input-only estimates mislead budgeting — output is ~40% of total cost.
    const expectedOutputTokens = Math.min(1500, request.maxOutputTokens);
    const estimatedCostUsd =
      (inputTokens / 1_000_000) * this.pricing.inputPerMTokUsd +
      (expectedOutputTokens / 1_000_000) * this.pricing.outputPerMTokUsd;
    return { inputTokens, estimatedCostUsd };
  }

  // NOTE: Anthropic reports input_tokens as the fresh (uncached) portion only.
  // cache_creation_input_tokens and cache_read_input_tokens are separate line items.
  // So we bill each at its own rate — NOT subtracting them from input_tokens.
  private computeCost(input: number, output: number, cacheRead: number, cacheWrite: number): number {
    const perM = (t: number, r: number) => (t / 1_000_000) * r;
    return (
      perM(input, this.pricing.inputPerMTokUsd) +
      perM(output, this.pricing.outputPerMTokUsd) +
      perM(cacheRead, this.pricing.cacheReadPerMTokUsd) +
      perM(cacheWrite, this.pricing.cacheWritePerMTokUsd)
    );
  }
}
