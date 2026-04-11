import { describe, it, expect } from "vitest";
import { BudgetTracker, type ProviderPricing } from "../../../src/layers/ai/budget.js";

// Contrived pricing: $1 per 1M in, $5 per 1M out, $0.10 per 1M cache read, $1.25 per 1M cache write.
const pricing: ProviderPricing = {
  inputPerMTokUsd: 1,
  outputPerMTokUsd: 5,
  cacheReadPerMTokUsd: 0.1,
  cacheWritePerMTokUsd: 1.25,
};

describe("BudgetTracker", () => {
  it("starts at zero cost", () => {
    const b = new BudgetTracker(2.0, pricing);
    expect(b.currentCostUsd()).toBe(0);
    expect(b.exhausted()).toBe(false);
  });

  it("accumulates usage across calls and computes cost", () => {
    const b = new BudgetTracker(10.0, pricing);
    b.recordUsage({
      inputTokens: 1_000_000,
      outputTokens: 200_000,
      cacheReadTokens: 500_000,
      cacheWriteTokens: 100_000,
      estimatedCostUsd: 0,
    });
    // Cost: 1*1 + 0.2*5 + 0.5*0.1 + 0.1*1.25 = 1 + 1 + 0.05 + 0.125 = 2.175
    expect(b.currentCostUsd()).toBeCloseTo(2.175, 4);
    expect(b.exhausted()).toBe(false);
  });

  it("exhausted() flips when cost crosses maxCostUsd", () => {
    const b = new BudgetTracker(2.0, pricing);
    b.recordUsage({
      inputTokens: 2_000_000,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      estimatedCostUsd: 0,
    });
    expect(b.currentCostUsd()).toBeCloseTo(2.0);
    expect(b.exhausted()).toBe(true);
  });

  it("wouldExceed returns true when estimate would cross cap", () => {
    const b = new BudgetTracker(2.0, pricing);
    b.recordUsage({
      inputTokens: 1_500_000,
      outputTokens: 0,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      estimatedCostUsd: 0,
    });
    // Already at $1.50. A $0.60 estimate would cross the $2.00 cap.
    expect(b.wouldExceed({ inputTokens: 0, estimatedCostUsd: 0.6 })).toBe(true);
    expect(b.wouldExceed({ inputTokens: 0, estimatedCostUsd: 0.4 })).toBe(false);
  });

  it("summary returns accumulated AIUsage with computed cost", () => {
    const b = new BudgetTracker(10.0, pricing);
    b.recordUsage({
      inputTokens: 1_000,
      outputTokens: 500,
      cacheReadTokens: 10_000,
      cacheWriteTokens: 0,
      estimatedCostUsd: 0,
    });
    b.recordUsage({
      inputTokens: 2_000,
      outputTokens: 1_000,
      cacheReadTokens: 20_000,
      cacheWriteTokens: 0,
      estimatedCostUsd: 0,
    });
    const s = b.summary();
    expect(s.inputTokens).toBe(3_000);
    expect(s.outputTokens).toBe(1_500);
    expect(s.cacheReadTokens).toBe(30_000);
    expect(s.cacheWriteTokens).toBe(0);
    expect(s.estimatedCostUsd).toBeGreaterThan(0);
  });
});
