import { describe, it, expect } from "vitest";
import { formatJson } from "../../src/output/json.js";
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
  title: "a",
  description: "",
  evidence: [],
  remediation: "",
  references: [],
  layer: "rules",
};

const findingB: Finding = {
  id: "TEST-2",
  domain: "input-injection",
  severity: "high",
  confidence: "medium",
  title: "b",
  description: "",
  evidence: [],
  remediation: "",
  references: [],
  layer: "rules",
};

function makeVerifyResult(overrides: Partial<VerifyResult> = {}): VerifyResult {
  return {
    confirmed: [findingA],
    dismissed: [{ finding: findingB, reason: "test fixture" }],
    downgraded: [
      {
        original: { ...findingA },
        finding: { ...findingA, severity: "low" },
        reason: "limited reachability",
      },
    ],
    usage: {
      inputTokens: 500,
      outputTokens: 100,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      estimatedCostUsd: 0.0021,
    },
    errors: [{ kind: "parse", message: "bad json", file: "/tmp/x.ts" }],
    budgetExhausted: false,
    filesProcessed: 3,
    findingsProcessed: 2,
    durationMs: 800,
    ...overrides,
  };
}

describe("json output (verify)", () => {
  it("omits the verification key when no verifyResult is passed", () => {
    const out = formatJson(model, [findingA], { recon_ms: 1, rules_ms: 1 });
    const parsed = JSON.parse(out);
    expect("verification" in parsed).toBe(false);
  });

  it("emits a verification object when verifyResult is provided", () => {
    const v = makeVerifyResult();
    const out = formatJson(model, [findingA], { recon_ms: 1, rules_ms: 1 }, v);
    const parsed = JSON.parse(out);
    expect(parsed.verification).toBeDefined();
    expect(Array.isArray(parsed.verification.confirmed)).toBe(true);
    expect(Array.isArray(parsed.verification.dismissed)).toBe(true);
    expect(Array.isArray(parsed.verification.downgraded)).toBe(true);
    expect(parsed.verification.budgetExhausted).toBe(false);
    expect(parsed.verification.filesProcessed).toBe(3);
    expect(parsed.verification.findingsProcessed).toBe(2);
  });

  it("dismissed entries carry finding and reason", () => {
    const v = makeVerifyResult();
    const out = formatJson(model, [findingA], { recon_ms: 1, rules_ms: 1 }, v);
    const parsed = JSON.parse(out);
    const d = parsed.verification.dismissed[0];
    expect(d.finding.id).toBe("TEST-2");
    expect(d.reason).toBe("test fixture");
  });

  it("downgraded entries carry original, finding, and reason", () => {
    const v = makeVerifyResult();
    const out = formatJson(model, [findingA], { recon_ms: 1, rules_ms: 1 }, v);
    const parsed = JSON.parse(out);
    const dg = parsed.verification.downgraded[0];
    expect(dg.original.severity).toBe("critical");
    expect(dg.finding.severity).toBe("low");
    expect(dg.reason).toBe("limited reachability");
  });

  it("passes errors through as an array", () => {
    const v = makeVerifyResult();
    const out = formatJson(model, [findingA], { recon_ms: 1, rules_ms: 1 }, v);
    const parsed = JSON.parse(out);
    expect(parsed.verification.errors.length).toBe(1);
    expect(parsed.verification.errors[0].kind).toBe("parse");
    expect(parsed.verification.errors[0].file).toBe("/tmp/x.ts");
  });

  it("passes usage and duration through correctly", () => {
    const v = makeVerifyResult();
    const out = formatJson(model, [findingA], { recon_ms: 1, rules_ms: 1 }, v);
    const parsed = JSON.parse(out);
    expect(parsed.verification.usage.estimatedCostUsd).toBe(0.0021);
    expect(parsed.verification.usage.inputTokens).toBe(500);
    expect(parsed.verification.durationMs).toBe(800);
  });
});
