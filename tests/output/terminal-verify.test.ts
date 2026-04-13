import { describe, it, expect } from "vitest";
import { formatTerminal } from "../../src/output/terminal.js";
import type {
  Finding,
  ProjectModel,
  VerifyResult,
} from "../../src/model/types.js";

const model: ProjectModel = {
  meta: {
    name: "test",
    path: "/tmp",
    stack: "nextjs-supabase",
    packageManager: "npm",
    language: "typescript",
    framework: "nextjs-app",
    deployTarget: null,
  },
  routes: [],
  endpoints: [],
  fileUploads: [],
  authFlows: [],
  dataModels: [],
  dependencies: [],
  envVars: [],
  staticAssets: [],
  findings: [],
} as unknown as ProjectModel;

const findingA: Finding = {
  id: "TEST-1",
  domain: "secrets-exposure",
  severity: "critical",
  confidence: "high",
  title: "hardcoded api key",
  description: "d",
  evidence: [{ file: "/tmp/a.ts", line: 10 }],
  remediation: "rotate",
  references: [],
  layer: "rules",
};

const findingB: Finding = {
  id: "TEST-2",
  domain: "input-injection",
  severity: "medium",
  confidence: "medium",
  title: "possible sql concat",
  description: "d",
  evidence: [{ file: "/tmp/b.ts", line: 22 }],
  remediation: "use params",
  references: [],
  layer: "rules",
};

function makeVerifyResult(overrides: Partial<VerifyResult> = {}): VerifyResult {
  return {
    confirmed: [findingA],
    dismissed: [{ finding: findingB, reason: "test-only file, not deployed" }],
    downgraded: [],
    usage: {
      inputTokens: 1000,
      outputTokens: 200,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      estimatedCostUsd: 0.0123,
    },
    errors: [],
    budgetExhausted: false,
    filesProcessed: 2,
    findingsProcessed: 2,
    durationMs: 1500,
    ...overrides,
  };
}

describe("terminal output (verify)", () => {
  it("is byte-identical when no verifyResult is passed", () => {
    const a = formatTerminal(model, [findingA, findingB]);
    const b = formatTerminal(model, [findingA, findingB], null);
    const c = formatTerminal(model, [findingA, findingB], undefined);
    expect(b).toBe(a);
    expect(c).toBe(a);
    expect(a).not.toContain("VERIFICATION");
  });

  it("renders a VERIFICATION block with counts", () => {
    const out = formatTerminal(model, [findingA], makeVerifyResult());
    expect(out).toContain("VERIFICATION");
    expect(out).toContain("Verified: 1 confirmed, 1 dismissed, 0 downgraded");
    expect(out).toContain("$0.0123");
    expect(out).toContain("1500ms");
  });

  it("includes DISMISSED section when keepDismissed=true", () => {
    const out = formatTerminal(
      model,
      [findingA],
      makeVerifyResult(),
      { keepDismissed: true },
    );
    expect(out).toContain("DISMISSED (SUSPECTED FALSE POSITIVE)");
    expect(out).toContain("TEST-2");
    expect(out).toContain("possible sql concat");
    expect(out).toContain("input-injection");
    expect(out).toContain("Dismissed: test-only file, not deployed");
  });

  it("omits DISMISSED section when keepDismissed=false (default)", () => {
    const out = formatTerminal(model, [findingA], makeVerifyResult());
    expect(out).toContain("VERIFICATION");
    expect(out).not.toContain("DISMISSED (SUSPECTED FALSE POSITIVE)");
  });

  it("shows verification error warning line", () => {
    const out = formatTerminal(
      model,
      [findingA],
      makeVerifyResult({
        errors: [
          { kind: "provider", message: "rate limit" },
          { kind: "parse", message: "bad json" },
        ],
      }),
    );
    expect(out).toContain("Verification errors: 2");
    expect(out).toContain("see JSON output");
  });

  it("renders downgraded count correctly", () => {
    const downgraded = {
      original: { ...findingA },
      finding: { ...findingA, severity: "medium" as const },
      reason: "lower exploit likelihood",
    };
    const out = formatTerminal(
      model,
      [findingA],
      makeVerifyResult({ downgraded: [downgraded] }),
    );
    expect(out).toContain("Verified: 1 confirmed, 1 dismissed, 1 downgraded");
  });
});
