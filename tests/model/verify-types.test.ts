import { describe, it, expect } from "vitest";
import { VerdictSchema } from "../../src/layers/ai/verify-schema.js";
import type {
  VerifyConfig,
  VerifyResult,
  Verdict,
  VerifyUsage,
} from "../../src/model/types.js";
import { CONFIG_DEFAULTS } from "../../src/config.js";

describe("verify types", () => {
  it("VerifyConfig has the required fields with correct types", () => {
    const cfg: VerifyConfig = {
      enabled: false,
      provider: "anthropic",
      model: "claude-haiku-4-5",
      maxCostUsd: 1.0,
      concurrency: 4,
      minSeverity: "medium",
      keepDismissed: false,
    };
    expect(cfg.enabled).toBe(false);
    expect(cfg.provider).toBe("anthropic");
    expect(cfg.minSeverity).toBe("medium");
  });

  it("VerifyResult has confirmed/dismissed/downgraded buckets plus metadata", () => {
    const result: VerifyResult = {
      confirmed: [],
      dismissed: [],
      downgraded: [],
      usage: {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        estimatedCostUsd: 0,
      },
      errors: [],
      budgetExhausted: false,
      filesProcessed: 0,
      findingsProcessed: 0,
      durationMs: 0,
    };
    expect(result.confirmed).toEqual([]);
    expect(result.usage.estimatedCostUsd).toBe(0);
    expect(result.budgetExhausted).toBe(false);
  });

  it("Verdict discriminates on decision", () => {
    const confirm: Verdict = {
      findingId: "CRYPTO-008-x-1",
      decision: "confirm",
      reason: "Real HMAC comparison using ==",
    };
    const dismiss: Verdict = {
      findingId: "CRYPTO-008-x-2",
      decision: "dismiss",
      reason: "Boolean comparison, not a secret",
    };
    const downgrade: Verdict = {
      findingId: "LOG-001-x-1",
      decision: "downgrade",
      reason: "Dev test page, reduce severity",
      newSeverity: "low",
    };
    expect(confirm.decision).toBe("confirm");
    expect(dismiss.decision).toBe("dismiss");
    expect(downgrade.newSeverity).toBe("low");
  });

  it("VerifyUsage mirrors AIUsage shape", () => {
    const usage: VerifyUsage = {
      inputTokens: 100,
      outputTokens: 50,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      estimatedCostUsd: 0.001,
    };
    expect(usage.inputTokens).toBe(100);
  });
});

describe("VerdictSchema (Zod)", () => {
  it("parses a confirm verdict", () => {
    const parsed = VerdictSchema.parse({
      findingId: "id-1",
      decision: "confirm",
      reason: "real issue",
    });
    expect(parsed.decision).toBe("confirm");
  });

  it("parses a dismiss verdict", () => {
    const parsed = VerdictSchema.parse({
      findingId: "id-2",
      decision: "dismiss",
      reason: "not actually a secret",
    });
    expect(parsed.decision).toBe("dismiss");
  });

  it("parses a downgrade verdict with newSeverity", () => {
    const parsed = VerdictSchema.parse({
      findingId: "id-3",
      decision: "downgrade",
      reason: "dev-only path",
      newSeverity: "low",
    });
    expect(parsed.newSeverity).toBe("low");
  });

  it("rejects a downgrade verdict missing newSeverity", () => {
    expect(() =>
      VerdictSchema.parse({
        findingId: "id-4",
        decision: "downgrade",
        reason: "no severity provided",
      }),
    ).toThrow();
  });

  it("rejects an unknown decision value", () => {
    expect(() =>
      VerdictSchema.parse({
        findingId: "id-5",
        decision: "maybe",
        reason: "unclear",
      }),
    ).toThrow();
  });

  it("rejects missing findingId", () => {
    expect(() =>
      VerdictSchema.parse({
        decision: "confirm",
        reason: "real",
      }),
    ).toThrow();
  });
});

describe("CONFIG_DEFAULTS.ai.verify", () => {
  it("has sane verify defaults", () => {
    const v = CONFIG_DEFAULTS.ai.verify;
    expect(v.enabled).toBe(false);
    expect(v.model).toBe("claude-haiku-4-5");
    expect(v.maxCostUsd).toBeGreaterThan(0);
    expect(v.concurrency).toBeGreaterThanOrEqual(1);
    expect(v.minSeverity).toBe("medium");
    expect(v.keepDismissed).toBe(false);
  });
});
