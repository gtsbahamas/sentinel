import { describe, it, expect } from "vitest";
import { verifyFindingsForFile } from "../../../src/layers/ai/verify.js";
import { BudgetTracker } from "../../../src/layers/ai/budget.js";
import type { AIUsage, Finding, Severity } from "../../../src/model/types.js";
import type {
  AIProvider,
  GenerateRequest,
  GenerateResponse,
} from "../../../src/layers/ai/providers/base.js";
import type { TokenEstimate } from "../../../src/layers/ai/budget.js";

const ZERO_USAGE: AIUsage = {
  inputTokens: 100,
  outputTokens: 50,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  estimatedCostUsd: 0,
};

function mkFinding(id: string, file: string, severity: Severity = "high"): Finding {
  return {
    id,
    domain: "cryptography",
    severity,
    confidence: "medium",
    title: `Finding ${id}`,
    description: "test",
    evidence: [{ file, line: 1, snippet: "x" }],
    remediation: "fix",
    references: [],
    layer: "rules",
    ruleId: "TEST-001",
  };
}

function wrapVerdicts(verdicts: unknown[]): GenerateResponse {
  return {
    rawFindings: [{ verdicts }],
    usage: { ...ZERO_USAGE },
    stopReason: "tool_use",
  };
}

class CannedProvider implements AIProvider {
  readonly name = "mock" as const;
  public callCount = 0;
  constructor(private readonly responder: (req: GenerateRequest, idx: number) => Promise<GenerateResponse> | GenerateResponse) {}
  async generateFindings(req: GenerateRequest): Promise<GenerateResponse> {
    return this.responder(req, this.callCount++);
  }
  estimateTokens(_req: GenerateRequest): TokenEstimate {
    return { inputTokens: 100, estimatedCostUsd: 0 };
  }
}

const FREE_PRICING = { inputPerMTokUsd: 0, outputPerMTokUsd: 0, cacheReadPerMTokUsd: 0, cacheWritePerMTokUsd: 0 };

describe("verifyFindingsForFile", () => {
  const findings = [
    mkFinding("f1", "a.ts"),
    mkFinding("f2", "a.ts"),
    mkFinding("f3", "a.ts"),
  ];

  it("happy path: maps confirm/dismiss/downgrade verdicts", async () => {
    const provider = new CannedProvider(() =>
      wrapVerdicts([
        { findingId: "f1", decision: "confirm", reason: "real bug", newSeverity: null },
        { findingId: "f2", decision: "dismiss", reason: "false positive", newSeverity: null },
        { findingId: "f3", decision: "downgrade", reason: "dev only", newSeverity: "low" },
      ]),
    );
    const budget = new BudgetTracker(10, FREE_PRICING);
    const result = await verifyFindingsForFile({
      file: "a.ts",
      source: "const a = 1;",
      findings,
      context: null,
      provider,
      budget,
    });
    expect(result.error).toBeNull();
    expect(result.verdicts).toHaveLength(3);
    expect(result.verdicts[0].decision).toBe("confirm");
    expect(result.verdicts[1].decision).toBe("dismiss");
    expect(result.verdicts[2].decision).toBe("downgrade");
    expect(result.verdicts[2].newSeverity).toBe("low");
  });

  it("provider error: confirms all with error reason", async () => {
    const provider = new CannedProvider(() => {
      throw new Error("api down");
    });
    const budget = new BudgetTracker(10, FREE_PRICING);
    const result = await verifyFindingsForFile({
      file: "a.ts",
      source: "x",
      findings,
      context: null,
      provider,
      budget,
    });
    expect(result.error?.kind).toBe("provider");
    expect(result.verdicts).toHaveLength(3);
    for (const v of result.verdicts) {
      expect(v.decision).toBe("confirm");
      expect(v.reason).toMatch(/^verification failed/);
    }
  });

  it("parse error: confirms all when verdict shape is invalid", async () => {
    const provider = new CannedProvider(() =>
      wrapVerdicts([
        { findingId: "f1", decision: "maybe", reason: "?", newSeverity: null },
        { findingId: "f2", decision: "downgrade", reason: "no severity", newSeverity: null },
        { findingId: "f3", decision: "confirm", reason: "ok", newSeverity: null },
      ]),
    );
    const budget = new BudgetTracker(10, FREE_PRICING);
    const result = await verifyFindingsForFile({
      file: "a.ts",
      source: "x",
      findings,
      context: null,
      provider,
      budget,
    });
    expect(result.error?.kind).toBe("parse");
    expect(result.verdicts).toHaveLength(3);
    for (const v of result.verdicts) expect(v.decision).toBe("confirm");
  });

  it("missing verdicts: defaults to confirm with 'no verdict returned'", async () => {
    const provider = new CannedProvider(() =>
      wrapVerdicts([
        { findingId: "f1", decision: "dismiss", reason: "fp", newSeverity: null },
        { findingId: "f2", decision: "confirm", reason: "ok", newSeverity: null },
      ]),
    );
    const budget = new BudgetTracker(10, FREE_PRICING);
    const result = await verifyFindingsForFile({
      file: "a.ts",
      source: "x",
      findings,
      context: null,
      provider,
      budget,
    });
    expect(result.error).toBeNull();
    const f3 = result.verdicts.find((v) => v.findingId === "f3");
    expect(f3?.decision).toBe("confirm");
    expect(f3?.reason).toBe("no verdict returned");
  });
});
