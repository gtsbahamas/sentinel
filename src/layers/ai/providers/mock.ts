import type { AIProvider, GenerateRequest, GenerateResponse } from "./base.js";
import type { TokenEstimate } from "../budget.js";

export interface MockDispatch {
  [userPromptKeyOrSubstring: string]: GenerateResponse;
}

/**
 * Deterministic test provider. Fails loudly on unknown keys.
 * Tests rely on this: any real network call would escape sandbox.
 */
export class MockProvider implements AIProvider {
  readonly name = "mock" as const;
  public callCount = 0;

  constructor(private readonly dispatch: MockDispatch) {}

  async generateFindings(request: GenerateRequest): Promise<GenerateResponse> {
    this.callCount++;
    // Match either exact userPrompt or a substring contained in it.
    for (const [key, value] of Object.entries(this.dispatch)) {
      if (request.userPrompt === key || request.userPrompt.includes(key)) {
        return value;
      }
    }
    throw new Error(
      `MockProvider: unknown key. No dispatch entry matched userPrompt=${request.userPrompt.slice(0, 60)}...`,
    );
  }

  estimateTokens(request: GenerateRequest): TokenEstimate {
    // ~4 chars per token, rounded up. Free in mock pricing.
    const approxInput = Math.ceil(
      (request.systemPrompt.length + request.projectSummary.length + request.userPrompt.length) / 4,
    );
    return { inputTokens: approxInput, estimatedCostUsd: 0 };
  }
}
