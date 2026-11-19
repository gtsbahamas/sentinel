import { describe, it, expect } from "vitest";
import { infrastructureRules } from "../../src/layers/rules/domains/infrastructure.js";
import { securityHeadersCheck } from "../../src/layers/probe/checks/passive/security-headers.js";
import { MockHttpClient } from "../../src/layers/probe/http-client.js";
import { ProbeCleanupRegistry } from "../../src/layers/probe/cleanup-registry.js";
import type { ProbeTarget, Severity } from "../../src/model/types.js";
import { emptyModel } from "../rules/helpers.js";

// A missing security header is found two ways: by reading the repo (the
// INFRA rules) and by asking the running site (the security-headers probe).
// The same missing header must carry the same severity both ways.

const RULE_FOR_HEADER: Record<string, string> = {
  "content-security-policy": "INFRA-001",
  "strict-transport-security": "INFRA-002",
  "x-frame-options": "INFRA-003",
  "referrer-policy": "INFRA-009",
};

async function ruleSeverities(ruleId: string): Promise<{ declared: Severity; emitted: Severity[] }> {
  const rule = infrastructureRules.find((r) => r.id === ruleId)!;
  const findings = await rule.check(emptyModel());
  return { declared: rule.severity, emitted: findings.map((f) => f.severity) };
}

async function probeSeverities(): Promise<Record<string, Severity>> {
  const target: ProbeTarget = { kind: "baseline", url: "http://localhost:3000", method: "GET", auth: "unauthenticated", fromLayer: "recon" };
  const client = new MockHttpClient([
    { match: { url: target.url }, response: { status: 200, headers: { "content-type": "text/html" }, body: "" } },
  ]);
  const result = await securityHeadersCheck.run({
    target,
    model: emptyModel(),
    client,
    registry: new ProbeCleanupRegistry(),
    priorFindings: [],
    runId: "header-severity",
  });
  return Object.fromEntries(result.findings.map((f) => [f.title.replace("Missing security header: ", ""), f.severity]));
}

describe("a missing security header has one severity", () => {
  for (const [header, ruleId] of Object.entries(RULE_FOR_HEADER)) {
    it(`${header}: ${ruleId} and the probe agree`, async () => {
      const rule = await ruleSeverities(ruleId);
      const probe = await probeSeverities();
      expect(rule.emitted).toEqual([rule.declared]);
      expect(probe[header]).toBe(rule.declared);
    });
  }
});

describe("the one table", () => {
  it("is what the rules and the probe both report", async () => {
    const { MISSING_HEADER_SEVERITY } = await import("../../src/model/header-severity.js");
    const probe = await probeSeverities();
    expect(probe).toEqual(MISSING_HEADER_SEVERITY);
    for (const [header, ruleId] of Object.entries(RULE_FOR_HEADER)) {
      expect((await ruleSeverities(ruleId)).declared).toBe(MISSING_HEADER_SEVERITY[header as keyof typeof MISSING_HEADER_SEVERITY]);
    }
  });

  it("a missing CSP is high wherever it is found", async () => {
    expect((await ruleSeverities("INFRA-001")).emitted).toEqual(["high"]);
    expect((await probeSeverities())["content-security-policy"]).toBe("high");
  });
});
