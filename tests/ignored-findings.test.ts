import { describe, it, expect } from "vitest";
import { splitIgnoredFindings } from "../src/utils/ignored-findings.js";
import { formatJson } from "../src/output/json.js";
import { formatTerminal } from "../src/output/terminal.js";
import { formatHtml } from "../src/output/html.js";
import type { Finding } from "../src/model/types.js";
import { emptyModel } from "./rules/helpers.js";

function finding(id: string, files: string[], severity: Finding["severity"] = "high"): Finding {
  return {
    id,
    ruleId: "INPUT-003",
    domain: "input-injection",
    severity,
    confidence: "high",
    title: `title of ${id}`,
    description: "",
    evidence: files.map((file) => ({ file, line: 7 })),
    remediation: "",
    references: [],
    layer: "rules",
  };
}

const model = emptyModel();
const kept = finding("KEPT-1", ["/tmp/test-project/src/app/api/users/route.ts"]);
const ignored = finding("IGNORED-1", ["/tmp/test-project/vendor/lib/db.ts"], "critical");

describe("findings under a path the config ignores", () => {
  it("are set aside, not thrown away", () => {
    const mixed = finding("MIXED-1", ["/tmp/test-project/vendor/lib/db.ts", "/tmp/test-project/src/lib/db.ts"]);
    const noEvidence = finding("BARE-1", []);
    const result = splitIgnoredFindings([kept, ignored, mixed, noEvidence], "/tmp/test-project", ["vendor"]);
    expect(result.ignored.map((f) => f.id)).toEqual(["IGNORED-1"]);
    // Evidence outside the ignored path keeps a finding in the report.
    expect(result.kept.map((f) => f.id)).toEqual(["KEPT-1", "MIXED-1", "BARE-1"]);
  });

  it("nothing is set aside when the config ignores nothing", () => {
    const result = splitIgnoredFindings([kept, ignored], "/tmp/test-project", []);
    expect(result.kept).toHaveLength(2);
    expect(result.ignored).toEqual([]);
  });

  it("the JSON report lists and counts them apart from the findings", () => {
    const report = JSON.parse(formatJson(model, [kept], { recon_ms: 1, rules_ms: 1 }, null, [ignored]));
    expect(report.findings.map((f: Finding) => f.id)).toEqual(["KEPT-1"]);
    expect(report.summary.total).toBe(1);
    expect(report.summary.critical).toBe(0);
    expect(report.summary.ignored).toBe(1);
    expect(report.ignored.map((f: Finding) => f.id)).toEqual(["IGNORED-1"]);
  });

  it("the JSON report says zero when there are none", () => {
    const report = JSON.parse(formatJson(model, [kept], { recon_ms: 1, rules_ms: 1 }));
    expect(report.summary.ignored).toBe(0);
    expect(report.ignored).toEqual([]);
  });

  it("the terminal report lists and counts them after the totals", () => {
    const out = formatTerminal(model, [kept], null, { ignored: [ignored] });
    expect(out).toContain("Total: 0 critical, 1 high");
    expect(out).toMatch(/IGNORED BY \.sentinelrc\.json \(1\)/);
    const tail = out.slice(out.indexOf("IGNORED BY"));
    expect(tail).toContain("IGNORED-1");
    expect(tail).toContain("title of IGNORED-1");
    expect(tail).toContain("vendor/lib/db.ts:7");
    expect(tail).not.toContain("KEPT-1");
  });

  it("the terminal report has no such section when there are none", () => {
    expect(formatTerminal(model, [kept])).not.toContain("IGNORED BY");
  });

  it("the HTML report lists and counts them, outside the severity totals", () => {
    const html = formatHtml(model, [kept], { recon_ms: 1, rules_ms: 1 }, [ignored]);
    expect(html).toContain("1 findings across 1 domains");
    expect(html).toMatch(/Ignored by \.sentinelrc\.json \(1\)/);
    const tail = html.slice(html.indexOf("Ignored by .sentinelrc.json"));
    expect(tail).toContain("IGNORED-1");
    expect(tail).toContain("title of IGNORED-1");
    expect(tail).toContain("vendor/lib/db.ts:7");
    expect(formatHtml(model, [kept], { recon_ms: 1, rules_ms: 1 })).not.toContain("Ignored by .sentinelrc.json");
  });
});
