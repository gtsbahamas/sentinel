import { describe, it, expect } from "vitest";
import { formatHtml } from "../../src/output/html.js";
import type { Finding, ProjectModel } from "../../src/model/types.js";

function model(): ProjectModel {
  return {
    meta: {
      name: "demo",
      path: "/tmp/demo",
      stack: "nextjs-supabase",
      packageManager: "npm",
      language: "typescript",
      framework: "nextjs-app",
      deployTarget: "vercel",
    },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: {
      nextConfig: null,
      middleware: null,
      vercelConfig: null,
      supabaseConfig: null,
      securityHeaders: {},
    },
    findings: [],
  };
}

function finding(sev: Finding["severity"], ruleId: string): Finding {
  return {
    id: `${ruleId}-x-0`,
    domain: "input-injection",
    severity: sev,
    confidence: "high",
    title: `Example ${ruleId}`,
    description: "description",
    evidence: [{ file: "src/x.ts", line: 10, snippet: "code()" }],
    remediation: "fix it",
    references: ["CWE-79"],
    layer: "rules",
    ruleId,
  };
}

describe("formatHtml", () => {
  it("renders a full HTML document with summary and findings", () => {
    const m = model();
    const findings = [finding("critical", "X-001"), finding("medium", "X-002")];
    const html = formatHtml(m, findings, { recon_ms: 10, rules_ms: 20 });
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("Sentinel Security Assessment");
    expect(html).toContain("Example X-001");
    expect(html).toContain("Example X-002");
    expect(html).toContain("CRITICAL");
    expect(html).toContain("MEDIUM");
    expect(html).toContain("src/x.ts:10");
  });

  it("escapes HTML-sensitive characters in findings", () => {
    const m = model();
    const f = finding("high", "X-001");
    f.title = `<script>alert('xss')</script>`;
    const html = formatHtml(m, [f], { recon_ms: 1, rules_ms: 1 });
    expect(html).not.toContain("<script>alert('xss')</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("handles zero findings gracefully", () => {
    const html = formatHtml(model(), [], { recon_ms: 1, rules_ms: 1 });
    expect(html).toContain("No findings");
  });
});
