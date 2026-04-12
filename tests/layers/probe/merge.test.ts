import { describe, it, expect } from "vitest";
import { mergeProbeResults } from "../../../src/layers/probe/merge.js";
import type { Finding } from "../../../src/model/types.js";
import type { ProbeCheckResult } from "../../../src/layers/probe/checks/base.js";

function makeFinding(id: string, confidence = "medium"): Finding {
  return {
    id,
    domain: "auth-access-control",
    severity: "high",
    confidence: confidence as Finding["confidence"],
    title: `Finding ${id}`,
    description: "",
    evidence: [],
    remediation: "",
    references: [],
    layer: "rules",
  };
}

const dummyEvidence = {
  requestId: "req-1",
  checkId: "test",
  aggressionLevel: "passive" as const,
  request: { method: "GET", url: "http://localhost", headers: {} },
  response: { status: 200, headers: {}, bodyPreview: "", timingMs: 10 },
};

describe("mergeProbeResults", () => {
  it("upgrades confirmed findings to confirmed confidence", () => {
    const existing = [makeFinding("F1")];
    const results: ProbeCheckResult[] = [
      {
        findings: [{
          id: "PF1", domain: "auth-access-control", severity: "high", confidence: "confirmed",
          title: "Confirmed", description: "", evidence: [], remediation: "", references: [],
          layer: "probe", probeEvidence: dummyEvidence, confirms: "F1",
        }],
        confirmed: [{ findingId: "F1" }],
        refuted: [],
        errors: [],
      },
    ];

    const result = mergeProbeResults(existing, results);
    expect(result.confirmedIds).toEqual(["F1"]);
    expect(result.findings[0].confidence).toBe("confirmed");
  });

  it("demotes refuted findings to low confidence", () => {
    const existing = [makeFinding("F2", "high")];
    const results: ProbeCheckResult[] = [
      {
        findings: [{
          id: "PF2", domain: "auth-access-control", severity: "info", confidence: "confirmed",
          title: "Refuted", description: "", evidence: [], remediation: "", references: [],
          layer: "probe", probeEvidence: dummyEvidence, refutes: "F2",
        }],
        confirmed: [],
        refuted: [{ findingId: "F2" }],
        errors: [],
      },
    ];

    const result = mergeProbeResults(existing, results);
    expect(result.refutedIds).toEqual(["F2"]);
    expect(result.findings[0].confidence).toBe("low");
  });

  it("collects new probe-only findings separately", () => {
    const existing = [makeFinding("F3")];
    const results: ProbeCheckResult[] = [
      {
        findings: [{
          id: "PF3", domain: "secrets-exposure", severity: "critical", confidence: "confirmed",
          title: "Secret in body", description: "", evidence: [], remediation: "", references: [],
          layer: "probe", probeEvidence: dummyEvidence,
        }],
        confirmed: [],
        refuted: [],
        errors: [],
      },
    ];

    const result = mergeProbeResults(existing, results);
    expect(result.newProbeFindings).toHaveLength(1);
    expect(result.newProbeFindings[0].id).toBe("PF3");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe("F3");
  });

  it("leaves unmatched findings untouched", () => {
    const existing = [makeFinding("F4"), makeFinding("F5")];
    const results: ProbeCheckResult[] = [];

    const result = mergeProbeResults(existing, results);
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0].confidence).toBe("medium");
    expect(result.confirmedIds).toEqual([]);
    expect(result.refutedIds).toEqual([]);
  });
});
