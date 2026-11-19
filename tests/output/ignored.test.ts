import { describe, it, expect } from "vitest";
import { formatJson } from "../../src/output/json.js";
import { formatTerminal } from "../../src/output/terminal.js";
import { formatHtml } from "../../src/output/html.js";
import { diffReports } from "../../src/commands/diff.js";
import type { Finding, IgnoredFinding } from "../../src/model/types.js";
import { emptyModel } from "../rules/helpers.js";

// An ignored finding must stay visible in every report: counted, and listed
// with the rule and the place the comment is. It never adds to the active
// totals.

function finding(ruleId: string, file: string, severity: Finding["severity"]): Finding {
  return {
    id: `${ruleId}-${file}-0`,
    ruleId,
    domain: "auth-access-control",
    severity,
    confidence: "high",
    title: `${ruleId} title`,
    description: "",
    impact: "",
    evidence: [{ file }],
    remediation: "",
    references: [],
    layer: "rules",
  };
}

const model = emptyModel();
const active = [finding("AUTH-001", "/p/src/a.ts", "critical")];
const ignored: IgnoredFinding[] = [
  { ruleId: "INPUT-001", file: "/p/src/page.tsx", line: 12, finding: finding("INPUT-001", "/p/src/page.tsx", "high") },
  { ruleId: "INFRA-005", file: "/p/src/cookie.ts", line: 4, finding: finding("INFRA-005", "/p/src/cookie.ts", "high") },
];
const timing = { recon_ms: 1, rules_ms: 1 };

describe("ignored findings in reports", () => {
  it("json: counted in the summary, listed, and kept out of the active totals", () => {
    const out = JSON.parse(formatJson(model, active, timing, null, [], ignored));
    expect(out.summary.total).toBe(1);
    expect(out.summary.high).toBe(0);
    expect(out.summary.ignored_by_comment).toBe(2);
    expect(out.summary.ignored).toBe(0);
    expect(out.findings).toHaveLength(1);
    expect(out.ignored_by_comment.map((i: IgnoredFinding) => [i.ruleId, i.file, i.line, i.finding.severity])).toEqual([
      ["INPUT-001", "/p/src/page.tsx", 12, "high"],
      ["INFRA-005", "/p/src/cookie.ts", 4, "high"],
    ]);
  });

  it("json: a scan with nothing ignored says so explicitly", () => {
    const out = JSON.parse(formatJson(model, active, timing));
    expect(out.summary.ignored_by_comment).toBe(0);
    expect(out.ignored_by_comment).toEqual([]);
  });

  it("terminal: a count and one line per ignored finding", () => {
    const out = formatTerminal(model, active, null, { ignoredByComment: ignored });
    expect(out).toContain("Ignored: 2");
    expect(out).toContain("IGNORED (2)");
    expect(out).toContain("INPUT-001");
    expect(out).toContain("/p/src/page.tsx:12");
    expect(out).toContain("INFRA-005");
    expect(out).toContain("/p/src/cookie.ts:4");
    expect(out).toMatch(/Total: 1 critical, 0 high/);
  });

  it("terminal: nothing ignored, nothing extra printed", () => {
    expect(formatTerminal(model, active)).not.toMatch(/ignored/i);
  });

  it("html: a count and one row per ignored finding", () => {
    const out = formatHtml(model, active, timing, [], ignored);
    expect(out).toContain("Ignored (2)");
    expect(out).toContain("INPUT-001");
    expect(out).toContain("/p/src/page.tsx:12");
    expect(out).toContain("/p/src/cookie.ts:4");
    expect(out).toContain("1 findings");
    expect(formatHtml(model, active, timing)).not.toContain("Ignored (");
  });

  it("diff: a finding that became ignored is reported as ignored, not resolved", () => {
    const gone = finding("SECRETS-002", "/p/src/gone.ts", "critical");
    const result = diffReports(
      { findings: [...active, ignored[0].finding, gone], ignored: [], ignoredByComment: [] },
      { findings: active, ignored: [], ignoredByComment: [ignored[0]] },
    );
    expect(result.removed.map((f) => f.ruleId)).toEqual(["SECRETS-002"]);
    expect(result.nowIgnored.map((f) => f.ruleId)).toEqual(["INPUT-001"]);
    expect(result.added).toEqual([]);
  });

  it("diff: a finding the config's `ignore` now covers is ignored too, beside a comment-ignored one", () => {
    const configIgnored = finding("CRYPTO-002", "/p/tools/hash.ts", "critical");
    const result = diffReports(
      { findings: [...active, ignored[0].finding, configIgnored], ignored: [], ignoredByComment: [] },
      { findings: active, ignored: [configIgnored], ignoredByComment: [ignored[0]] },
    );
    expect(result.removed).toEqual([]);
    expect(result.nowIgnored.map((f) => f.ruleId).sort()).toEqual(["CRYPTO-002", "INPUT-001"]);
  });
});
