import type { AIProvider, GenerateRequest, GenerateResponse } from "./base.js";
import type { ProviderPricing, TokenEstimate } from "../budget.js";

// Pricing per 1M tokens. Update when OpenAI publishes new rates.
export const OPENAI_PRICING: Record<string, ProviderPricing> = {
  "gpt-5": { inputPerMTokUsd: 5, outputPerMTokUsd: 20, cacheReadPerMTokUsd: 2.5, cacheWritePerMTokUsd: 5 },
  "gpt-5-mini": { inputPerMTokUsd: 1, outputPerMTokUsd: 4, cacheReadPerMTokUsd: 0.5, cacheWritePerMTokUsd: 1 },
};

interface OpenAILike {
  chat: {
    completions: {
      create: (args: ChatCompletionArgs) => Promise<ChatCompletionResponse>;
    };
  };
}

interface ChatCompletionArgs {
  model: string;
  messages: Array<{ role: "system" | "user"; content: string }>;
  response_format: {
    type: "json_schema";
    json_schema: { name: string; strict: true; schema: object };
  };
  max_completion_tokens: number;
}

interface ChatCompletionResponse {
  choices: Array<{
    message: { content: string | null };
    finish_reason: string;
  }>;
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    prompt_tokens_details?: { cached_tokens?: number };
  };
}

const CHARS_PER_TOKEN = 4;

export class OpenAIProvider implements AIProvider {
  readonly name = "openai" as const;
  private readonly pricing: ProviderPricing;

  constructor(
    private readonly model: string,
    private readonly client: OpenAILike,
  ) {
    this.pricing = OPENAI_PRICING[model] ?? OPENAI_PRICING["gpt-5"];
  }

  async generateFindings(request: GenerateRequest): Promise<GenerateResponse> {
    try {
      const response = await this.client.chat.completions.create({
        model: this.model,
        messages: [
          { role: "system", content: `${request.systemPrompt}\n\n${request.projectSummary}` },
          { role: "user", content: request.userPrompt },
        ],
        response_format: {
          type: "json_schema",
          json_schema: {
            name: request.toolDefinition.name,
            strict: true,
            schema: request.toolDefinition.schema,
          },
        },
        max_completion_tokens: request.maxOutputTokens,
      });

      const choice = response.choices[0];
      const content = choice?.message?.content ?? "";
      let rawFindings: unknown[] = [];
      let stopReason: GenerateResponse["stopReason"] = "end_turn";

      // Tool-aware extraction: each known tool has its own top-level array key.
      const extractionKey = ((): string => {
        if (request.toolDefinition.name === "report_verdicts") return "verdicts";
        if (request.toolDefinition.name === "report_project_risks") return "projectRisks";
        return "findings";
      })();

      try {
        const parsed = JSON.parse(content) as Record<string, unknown>;
        const arr = parsed[extractionKey];
        if (Array.isArray(arr)) rawFindings = arr;
      } catch {
        stopReason = "error";
      }

      // NOTE: OpenAI's prompt_tokens INCLUDES cached tokens (unlike Anthropic's input_tokens
      // which excludes them). Cost formula subtracts cached from prompt to avoid double-counting:
      //   freshInput = prompt_tokens - cached_tokens
      // This is intentionally different from the Anthropic provider which uses additive math.
      const cached = response.usage.prompt_tokens_details?.cached_tokens ?? 0;
      return {
        rawFindings,
        stopReason,
        usage: {
          inputTokens: response.usage.prompt_tokens,
          outputTokens: response.usage.completion_tokens,
          cacheReadTokens: cached,
          cacheWriteTokens: 0,
          estimatedCostUsd: this.computeCost(response.usage.prompt_tokens, response.usage.completion_tokens, cached),
        },
        rawError: stopReason === "error" ? "malformed json content" : undefined,
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
    // Realistic baseline from live smoke tests: gpt-5 is a reasoning model,
    // averaging ~2500-3500 completion tokens per endpoint (reasoning tokens
    // count against max_completion_tokens). Use 3000 capped at maxOutputTokens.
    const expectedOutputTokens = Math.min(3000, request.maxOutputTokens);
    const estimatedCostUsd =
      (inputTokens / 1_000_000) * this.pricing.inputPerMTokUsd +
      (expectedOutputTokens / 1_000_000) * this.pricing.outputPerMTokUsd;
    return { inputTokens, estimatedCostUsd };
  }

  private computeCost(input: number, output: number, cached: number): number {
    const perM = (t: number, r: number) => (t / 1_000_000) * r;
    // OpenAI: prompt_tokens includes cached, so subtract to get fresh portion
    const freshInput = Math.max(0, input - cached);
    return (
      perM(freshInput, this.pricing.inputPerMTokUsd) +
      perM(cached, this.pricing.cacheReadPerMTokUsd) +
      perM(output, this.pricing.outputPerMTokUsd)
    );
  }
}
