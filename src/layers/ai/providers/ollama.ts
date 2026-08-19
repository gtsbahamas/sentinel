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
export const OLLAMA_DEEP_MODEL = "qwen3.6:27b";

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

      const DOMAINS = [
        "secrets-exposure", "input-injection", "auth-access-control", "file-upload",
        "api-security", "cryptography", "supply-chain", "infrastructure",
        "business-logic", "logging-monitoring", "llm-features",
      ];

      const jsonInstruction = extractionKey === "findings"
        ? [
            "\n\n---",
            `Respond ONLY with a valid JSON object. The top-level key must be "findings" containing an array.`,
            "Do NOT wrap the JSON in markdown code fences. Output raw JSON only.",
            "",
            "Each finding MUST have ALL of these fields (missing fields = rejected):",
            `  "ruleId": string matching AI-CATEGORY-NNN (e.g. "AI-AUTH-001")`,
            `  "domain": one of: ${DOMAINS.map(d => `"${d}"`).join(", ")}`,
            `  "severity": one of: "critical", "high", "medium", "low", "info"`,
            `  "confidence": one of: "high", "medium", "low"`,
            `  "title": string (10-200 chars)`,
            `  "description": string (20-2000 chars)`,
            `  "evidence": array of {"file": string, "line": number, "snippet": string}`,
            `  "impact": string (10-1000 chars)`,
            `  "remediation": string (20-1000 chars, specific fix instructions)`,
            `  "reasoning": string (20-2000 chars, your analysis)`,
            "",
            "If no issues found, return: {\"findings\": []}",
          ].join("\n")
        : [
            "\n\n---",
            `Respond ONLY with a valid JSON object matching the tool "${request.toolDefinition.name}".`,
            `The top-level key must be "${extractionKey}" containing an array.`,
            extractionKey === "projectRisks"
              ? `Each risk MUST have: "domain" (one of: ${DOMAINS.map(d => `"${d}"`).join(", ")}), "description", "affectedEndpoints" (array of path strings), "severity" (critical|high|medium|low|info). Also include a "priorityOrder" array of endpoint paths sorted most-risky first.`
              : "",
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
        if (Array.isArray(arr)) {
          // Patch up common Ollama omissions: infer domain from ruleId category
          rawFindings = arr.map((f: unknown) => {
            if (f && typeof f === "object" && !("domain" in (f as Record<string, unknown>))) {
              const obj = f as Record<string, unknown>;
              const ruleId = typeof obj.ruleId === "string" ? obj.ruleId : "";
              const cat = ruleId.replace(/^AI-/, "").replace(/-\d{3}$/, "").toLowerCase();
              const domainMap: Record<string, string> = {
                auth: "auth-access-control", idor: "auth-access-control",
                inject: "input-injection", input: "input-injection", xss: "input-injection", sqli: "input-injection",
                secret: "secrets-exposure", secrets: "secrets-exposure", cred: "secrets-exposure",
                upload: "file-upload", file: "file-upload",
                api: "api-security", rate: "api-security", ratelimit: "api-security",
                crypto: "cryptography", tls: "cryptography",
                supply: "supply-chain", dep: "supply-chain",
                infra: "infrastructure", csp: "infrastructure", header: "infrastructure",
                biz: "business-logic", logic: "business-logic",
                log: "logging-monitoring", monitor: "logging-monitoring", error: "logging-monitoring",
                info: "logging-monitoring",
                llm: "llm-features", prompt: "llm-features", ai: "llm-features",
              };
              obj.domain = domainMap[cat] ?? "api-security";
            }
            return f;
          });
        }
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
