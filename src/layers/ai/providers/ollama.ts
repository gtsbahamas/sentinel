import type { AIProvider, GenerateRequest, GenerateResponse } from "./base.js";
import type { ProviderPricing, TokenEstimate } from "../budget.js";

// Ollama is free — all rates are zero.
export const OLLAMA_PRICING: ProviderPricing = {
  inputPerMTokUsd: 0,
  outputPerMTokUsd: 0,
  cacheReadPerMTokUsd: 0,
  cacheWritePerMTokUsd: 0,
};

export const OLLAMA_DEFAULT_BASE_URL = "http://192.168.1.90:11434/v1";
export const OLLAMA_DEFAULT_MODEL = "llama3.1:8b";
export const OLLAMA_DEEP_MODEL = "qwen2.5:14b";

/**
 * OpenAI-compatible interface — only the subset we use.
 * Ollama's /v1/chat/completions endpoint implements this.
 */
interface OpenAILike {
  chat: {
    completions: {
      create: (args: Record<string, unknown>) => Promise<ChatCompletionResponse>;
    };
  };
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

/**
 * OllamaProvider talks to a local Ollama server via its OpenAI-compatible API.
 *
 * Key differences from OpenAIProvider:
 * - Uses a custom baseURL (defaults to local Ollama server)
 * - No API key required (dummy key satisfies the OpenAI SDK)
 * - Does NOT send `response_format: { type: "json_schema" }` because most
 *   Ollama models don't support structured output. Instead it asks for JSON
 *   in the system prompt and parses the response.
 * - All pricing is zero (local inference).
 */
export class OllamaProvider implements AIProvider {
  readonly name = "ollama" as const;

  constructor(
    private readonly model: string,
    private readonly client: OpenAILike,
  ) {}

  async generateFindings(request: GenerateRequest): Promise<GenerateResponse> {
    try {
      // Append a JSON instruction to the system prompt since we can't use
      // response_format with most Ollama models.
      const extractionKey = ((): string => {
        if (request.toolDefinition.name === "report_verdicts") return "verdicts";
        if (request.toolDefinition.name === "report_project_risks") return "projectRisks";
        return "findings";
      })();

      const jsonInstruction = [
        "\n\n---",
        `Respond ONLY with a valid JSON object matching the tool "${request.toolDefinition.name}".`,
        `The top-level key must be "${extractionKey}" containing an array.`,
        "Do NOT wrap the JSON in markdown code fences. Output raw JSON only.",
      ].join("\n");

      const response = await this.client.chat.completions.create({
        model: this.model,
        messages: [
          { role: "system", content: `${request.systemPrompt}\n\n${request.projectSummary}${jsonInstruction}` },
          { role: "user", content: request.userPrompt },
        ],
        max_completion_tokens: request.maxOutputTokens,
      });

      const choice = response.choices[0];
      const content = choice?.message?.content ?? "";
      let rawFindings: unknown[] = [];
      let stopReason: GenerateResponse["stopReason"] = "end_turn";

      try {
        // Strip markdown code fences if the model wraps its output.
        const cleaned = content.replace(/^```(?:json)?\s*\n?/i, "").replace(/\n?```\s*$/i, "").trim();
        const parsed = JSON.parse(cleaned) as Record<string, unknown>;
        const arr = parsed[extractionKey];
        if (Array.isArray(arr)) rawFindings = arr;
      } catch {
        stopReason = "error";
      }

      return {
        rawFindings,
        stopReason,
        usage: {
          inputTokens: response.usage.prompt_tokens,
          outputTokens: response.usage.completion_tokens,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          estimatedCostUsd: 0,
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
    return { inputTokens, estimatedCostUsd: 0 };
  }
}
