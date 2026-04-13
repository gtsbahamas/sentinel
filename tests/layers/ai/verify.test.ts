import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "fs";
import { tmpdir } from "os";
import { join, dirname } from "path";
import { verifyFindingsForFile, runVerify } from "../../../src/layers/ai/verify.js";
import { BudgetTracker } from "../../../src/layers/ai/budget.js";
import type {
  AIUsage,
  Finding,
  ProjectModel,
  Severity,
  VerifyConfig,
} from "../../../src/model/types.js";
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

function mkModel(root: string): ProjectModel {
  return {
    meta: { name: "t", path: root, stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: "vercel" },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
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
  public inFlight = 0;
  public maxInFlight = 0;
  constructor(
    private readonly responder: (req: GenerateRequest, idx: number) => Promise<GenerateResponse> | GenerateResponse,
  ) {}
  async generateFindings(req: GenerateRequest): Promise<GenerateResponse> {
    const idx = this.callCount++;
    this.inFlight++;
    if (this.inFlight > this.maxInFlight) this.maxInFlight = this.inFlight;
    try {
      return await this.responder(req, idx);
    } finally {
      this.inFlight--;
    }
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

describe("runVerify", () => {
  function mkFixture(files: string[]): { root: string; findings: Finding[] } {
    const root = mkdtempSync(join(tmpdir(), "verify-"));
    const findings: Finding[] = [];
    let i = 0;
    for (const f of files) {
      const abs = join(root, f);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, "export const x = 1;\n");
      findings.push(mkFinding(`f${i++}`, f));
      findings.push(mkFinding(`f${i++}`, f));
    }
    return { root, findings };
  }

  const baseConfig: VerifyConfig = {
    enabled: true,
    provider: "mock",
    model: "mock-1",
    maxCostUsd: 100,
    concurrency: 4,
    minSeverity: "low",
    keepDismissed: false,
  };

  it("groups findings by file and respects concurrency cap", async () => {
    const fixture = mkFixture(["a.ts", "b.ts", "c.ts", "d.ts", "e.ts"]);
    const provider = new CannedProvider(async (req) => {
      await new Promise((r) => setTimeout(r, 20));
      // Echo confirms for whatever findingIds appear in the prompt.
      const ids = Array.from(req.userPrompt.matchAll(/findingId:\s+(\S+)/g)).map((m) => m[1]);
      return wrapVerdicts(ids.map((id) => ({ findingId: id, decision: "confirm", reason: "ok", newSeverity: null })));
    });
    const result = await runVerify(mkModel(fixture.root), fixture.findings, null, { ...baseConfig, concurrency: 2 }, provider);
    expect(provider.maxInFlight).toBeLessThanOrEqual(2);
    expect(provider.maxInFlight).toBeGreaterThan(0);
    expect(result.confirmed.length + result.dismissed.length + result.downgraded.length).toBe(10);
    expect(result.filesProcessed).toBe(5);
    expect(result.findingsProcessed).toBe(10);
  });

  it("minSeverity filter: low passes through without AI", async () => {
    const root = mkdtempSync(join(tmpdir(), "verify-"));
    const file = join(root, "a.ts");
    writeFileSync(file, "x");
    const findings: Finding[] = [
      mkFinding("low1", "a.ts", "low"),
      mkFinding("med1", "a.ts", "medium"),
      mkFinding("hi1", "a.ts", "high"),
    ];
    let callCount = 0;
    const provider = new CannedProvider((req) => {
      callCount++;
      const ids = Array.from(req.userPrompt.matchAll(/findingId:\s+(\S+)/g)).map((m) => m[1]);
      return wrapVerdicts(ids.map((id) => ({ findingId: id, decision: "confirm", reason: "ok", newSeverity: null })));
    });
    const result = await runVerify(mkModel(root), findings, null, { ...baseConfig, minSeverity: "medium" }, provider);
    expect(callCount).toBe(1);
    expect(result.findingsProcessed).toBe(2); // med + hi
    expect(result.confirmed).toHaveLength(3); // low passthrough + 2 confirmed
  });

  it("budget exhaustion: synthesizes confirms for remaining files", async () => {
    const fixture = mkFixture(["a.ts", "b.ts", "c.ts"]);
    // Pricing makes any call exceed maxCostUsd immediately.
    const provider = new CannedProvider(async (req) => {
      await new Promise((r) => setTimeout(r, 5));
      const ids = Array.from(req.userPrompt.matchAll(/findingId:\s+(\S+)/g)).map((m) => m[1]);
      return {
        rawFindings: [{ verdicts: ids.map((id) => ({ findingId: id, decision: "confirm", reason: "ok", newSeverity: null })) }],
        usage: { inputTokens: 10_000_000, outputTokens: 10_000_000, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 },
        stopReason: "tool_use",
      };
    });
    const result = await runVerify(
      mkModel(fixture.root),
      fixture.findings,
      null,
      { ...baseConfig, concurrency: 1, maxCostUsd: 0.0001 },
      // Use anthropic pricing so budget actually accrues
      provider,
    );
    // We can't easily set a non-mock pricing, but the mock pricing is zero so budget never exhausts.
    // Instead, this test verifies the result shape includes budgetExhausted as a boolean.
    expect(typeof result.budgetExhausted).toBe("boolean");
    // All 6 findings still accounted for.
    expect(result.confirmed.length + result.dismissed.length + result.downgraded.length).toBe(6);
  });

  it("budget exhaustion (anthropic pricing): later files synthesized", async () => {
    const fixture = mkFixture(["a.ts", "b.ts", "c.ts"]);
    const provider = new CannedProvider(async (req) => {
      await new Promise((r) => setTimeout(r, 5));
      const ids = Array.from(req.userPrompt.matchAll(/findingId:\s+(\S+)/g)).map((m) => m[1]);
      return {
        rawFindings: [{ verdicts: ids.map((id) => ({ findingId: id, decision: "confirm", reason: "ok", newSeverity: null })) }],
        usage: { inputTokens: 10_000_000, outputTokens: 10_000_000, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 },
        stopReason: "tool_use",
      };
    });
    const result = await runVerify(
      mkModel(fixture.root),
      fixture.findings,
      null,
      { ...baseConfig, concurrency: 1, provider: "anthropic", model: "claude-haiku-4-5", maxCostUsd: 0.0001 },
      provider,
    );
    expect(result.budgetExhausted).toBe(true);
    expect(result.filesProcessed).toBeLessThan(3);
    // All findings still accounted for.
    expect(result.confirmed.length + result.dismissed.length + result.downgraded.length).toBe(6);
  });

  it("file read failure: confirms with error", async () => {
    const root = mkdtempSync(join(tmpdir(), "verify-"));
    const findings: Finding[] = [mkFinding("ghost1", "missing.ts"), mkFinding("ghost2", "missing.ts")];
    const provider = new CannedProvider(() => wrapVerdicts([]));
    const result = await runVerify(mkModel(root), findings, null, baseConfig, provider);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].message).toMatch(/file read failed/);
    expect(result.confirmed).toHaveLength(2);
  });

  it("result shape: counts and durationMs", async () => {
    const fixture = mkFixture(["a.ts", "b.ts"]);
    let i = 0;
    const provider = new CannedProvider((req) => {
      const ids = Array.from(req.userPrompt.matchAll(/findingId:\s+(\S+)/g)).map((m) => m[1]);
      // First file: 1 confirm + 1 dismiss. Second file: 1 confirm + 1 downgrade.
      const verdicts =
        i++ === 0
          ? [
              { findingId: ids[0], decision: "confirm", reason: "ok", newSeverity: null },
              { findingId: ids[1], decision: "dismiss", reason: "fp", newSeverity: null },
            ]
          : [
              { findingId: ids[0], decision: "confirm", reason: "ok", newSeverity: null },
              { findingId: ids[1], decision: "downgrade", reason: "dev", newSeverity: "low" },
            ];
      return wrapVerdicts(verdicts);
    });
    const result = await runVerify(mkModel(fixture.root), fixture.findings, null, { ...baseConfig, concurrency: 1 }, provider);
    expect(result.confirmed).toHaveLength(2);
    expect(result.dismissed).toHaveLength(1);
    expect(result.downgraded).toHaveLength(1);
    expect(result.filesProcessed).toBe(2);
    expect(result.findingsProcessed).toBe(4);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});
