import type { AIUsage } from "../../model/types.js";

export interface ProviderPricing {
  inputPerMTokUsd: number;
  outputPerMTokUsd: number;
  cacheReadPerMTokUsd: number;
  cacheWritePerMTokUsd: number;
}

export interface TokenEstimate {
  inputTokens: number;
  estimatedCostUsd: number;
}

export class BudgetTracker {
  private totalInput = 0;
  private totalOutput = 0;
  private totalCacheRead = 0;
  private totalCacheWrite = 0;

  constructor(
    private readonly maxCostUsd: number,
    private readonly pricing: ProviderPricing,
  ) {}

  recordUsage(usage: AIUsage): void {
    this.totalInput += usage.inputTokens;
    this.totalOutput += usage.outputTokens;
    this.totalCacheRead += usage.cacheReadTokens;
    this.totalCacheWrite += usage.cacheWriteTokens;
  }

  currentCostUsd(): number {
    const perM = (t: number, rate: number) => (t / 1_000_000) * rate;
    return (
      perM(this.totalInput, this.pricing.inputPerMTokUsd) +
      perM(this.totalOutput, this.pricing.outputPerMTokUsd) +
      perM(this.totalCacheRead, this.pricing.cacheReadPerMTokUsd) +
      perM(this.totalCacheWrite, this.pricing.cacheWritePerMTokUsd)
    );
  }

  wouldExceed(estimate: TokenEstimate): boolean {
    return this.currentCostUsd() + estimate.estimatedCostUsd > this.maxCostUsd;
  }

  exhausted(): boolean {
    return this.currentCostUsd() >= this.maxCostUsd;
  }

  summary(): AIUsage {
    return {
      inputTokens: this.totalInput,
      outputTokens: this.totalOutput,
      cacheReadTokens: this.totalCacheRead,
      cacheWriteTokens: this.totalCacheWrite,
      estimatedCostUsd: this.currentCostUsd(),
    };
  }
}
