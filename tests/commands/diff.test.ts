import { describe, it, expect } from "vitest";
import { diffFindings } from "../../src/commands/diff.js";
import type { Finding } from "../../src/model/types.js";

function f(overrides: Partial<Finding>): Finding {
  return {
    id: "X-file-1",
    domain: "input-injection",
    severity: "high",
    confidence: "high",
    title: "x",
    description: "x",
    evidence: [{ file: "a.ts", line: 1 }],
    remediation: "x",
    references: [],
    layer: "rules",
    ruleId: "X-001",
    ...overrides,
  };
}

describe("diffFindings", () => {
  it("reports added, removed, and unchanged", () => {
    const baseline = [
      f({ ruleId: "X-001", evidence: [{ file: "a.ts", line: 1 }] }),
      f({ ruleId: "X-002", evidence: [{ file: "b.ts", line: 2 }] }),
    ];
    const current = [
      f({ ruleId: "X-002", evidence: [{ file: "b.ts", line: 2 }] }),
      f({ ruleId: "X-003", evidence: [{ file: "c.ts", line: 3 }] }),
    ];
    const result = diffFindings(baseline, current);
    expect(result.added.map((x) => x.ruleId)).toEqual(["X-003"]);
    expect(result.removed.map((x) => x.ruleId)).toEqual(["X-001"]);
    expect(result.unchanged.map((x) => x.ruleId)).toEqual(["X-002"]);
    expect(result.baselineTotal).toBe(2);
    expect(result.currentTotal).toBe(2);
  });

  it("handles empty reports", () => {
    const result = diffFindings([], []);
    expect(result.added).toEqual([]);
    expect(result.removed).toEqual([]);
    expect(result.unchanged).toEqual([]);
  });

  it("treats the same finding at different lines as separate", () => {
    const baseline = [f({ ruleId: "X-001", evidence: [{ file: "a.ts", line: 1 }] })];
    const current = [f({ ruleId: "X-001", evidence: [{ file: "a.ts", line: 10 }] })];
    const result = diffFindings(baseline, current);
    expect(result.added.length).toBe(1);
    expect(result.removed.length).toBe(1);
    expect(result.unchanged.length).toBe(0);
  });
});
