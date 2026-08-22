import { describe, it, expect } from "vitest";
import { dedupAIFindings, normalizeTitle, classifyIssueTag } from "../../../src/layers/ai/dedup.js";
import type { Finding } from "../../../src/model/types.js";

function mkFinding(overrides: Partial<Finding> & Pick<Finding, "title">): Finding {
  return {
    id: overrides.id ?? `ai:${overrides.title}`,
    domain: overrides.domain ?? "auth-access-control",
    severity: overrides.severity ?? "high",
    confidence: overrides.confidence ?? "medium",
    title: overrides.title,
    description: overrides.description ?? "Test description for dedup.",
    evidence: overrides.evidence ?? [{ file: "src/app/api/users/route.ts", line: 10 }],
    remediation: overrides.remediation ?? "Add an auth check.",
    references: overrides.references ?? [],
    layer: overrides.layer ?? "ai",
    ruleId: overrides.ruleId ?? "AI-AUTH-001",
  };
}

describe("normalizeTitle", () => {
  it("strips HTTP method verbs", () => {
    expect(normalizeTitle("Missing auth on GET handler")).toBe("missing auth on");
    expect(normalizeTitle("Missing auth on POST handler")).toBe("missing auth on");
    expect(normalizeTitle("GET /api/users lacks ownership check")).toBe("/api/users lacks ownership check");
  });

  it("strips handler/endpoint/route boilerplate words", () => {
    expect(normalizeTitle("Missing auth handler")).toBe("missing auth");
    expect(normalizeTitle("Missing auth endpoint")).toBe("missing auth");
    expect(normalizeTitle("Missing auth route")).toBe("missing auth");
  });

  it("removes punctuation and collapses whitespace", () => {
    expect(normalizeTitle("Auth:   missing!  (yes, really)")).toBe("auth missing yes really");
  });

  it("collapses GET/POST variants of the same title to the same key", () => {
    const a = normalizeTitle("Missing authentication on GET handler for /api/users");
    const b = normalizeTitle("Missing authentication on POST handler for /api/users");
    expect(a).toBe(b);
  });

  it("does NOT collapse titles that are genuinely different", () => {
    const a = normalizeTitle("Missing auth on /api/users");
    const b = normalizeTitle("Broken ownership check on /api/users");
    expect(a).not.toBe(b);
  });
});

describe("dedupAIFindings", () => {
  it("leaves a single finding untouched", () => {
    const input = [mkFinding({ title: "Missing auth on GET handler for /api/users" })];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(1);
    expect(result.collapsedCount).toBe(0);
  });

  it("collapses GET/POST variants on the same file+domain", () => {
    const input = [
      mkFinding({
        title: "Missing authentication on GET handler for /api/users",
        evidence: [{ file: "src/app/api/users/route.ts", line: 10 }],
        severity: "high",
      }),
      mkFinding({
        title: "Missing authentication on POST handler for /api/users",
        evidence: [{ file: "src/app/api/users/route.ts", line: 30 }],
        severity: "high",
      }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(1);
    expect(result.collapsedCount).toBe(1);
    // Evidence from both should be merged on the representative.
    const merged = result.findings[0];
    expect(merged.evidence).toHaveLength(2);
    expect(merged.evidence.map((e) => e.line).sort()).toEqual([10, 30]);
  });

  it("keeps the strongest severity as the representative", () => {
    const input = [
      mkFinding({
        title: "Missing auth on GET handler",
        severity: "medium",
        confidence: "medium",
      }),
      mkFinding({
        title: "Missing auth on POST handler",
        severity: "critical",
        confidence: "high",
      }),
      mkFinding({
        title: "Missing auth on PATCH handler",
        severity: "high",
        confidence: "high",
      }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.findings[0].confidence).toBe("high");
    expect(result.collapsedCount).toBe(2);
  });

  it("breaks ties by confidence when severities match", () => {
    const input = [
      mkFinding({ title: "Missing auth on GET handler", severity: "high", confidence: "medium" }),
      mkFinding({ title: "Missing auth on POST handler", severity: "high", confidence: "high" }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings[0].confidence).toBe("high");
  });

  it("does NOT merge findings from different files", () => {
    const input = [
      mkFinding({
        title: "Missing auth on GET handler",
        evidence: [{ file: "src/app/api/users/route.ts", line: 10 }],
      }),
      mkFinding({
        title: "Missing auth on GET handler",
        evidence: [{ file: "src/app/api/products/route.ts", line: 10 }],
      }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(2);
    expect(result.collapsedCount).toBe(0);
  });

  it("does NOT merge findings from different domains", () => {
    const input = [
      mkFinding({
        title: "Missing validation on GET handler",
        domain: "input-injection",
      }),
      mkFinding({
        title: "Missing validation on POST handler",
        domain: "auth-access-control",
      }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(2);
    expect(result.collapsedCount).toBe(0);
  });

  it("does NOT merge findings with different normalized titles on the same file", () => {
    const input = [
      mkFinding({ title: "Missing authentication check" }),
      mkFinding({ title: "Missing CSRF token validation" }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(2);
    expect(result.collapsedCount).toBe(0);
  });

  it("deduplicates evidence entries with the same file+line", () => {
    const input = [
      mkFinding({
        title: "Missing auth on GET handler",
        evidence: [
          { file: "src/app/api/users/route.ts", line: 10 },
          { file: "src/app/api/users/route.ts", line: 20 },
        ],
      }),
      mkFinding({
        title: "Missing auth on POST handler",
        evidence: [
          { file: "src/app/api/users/route.ts", line: 10 },
          { file: "src/app/api/users/route.ts", line: 30 },
        ],
      }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].evidence).toHaveLength(3);
    const lines = result.findings[0].evidence.map((e) => e.line).sort();
    expect(lines).toEqual([10, 20, 30]);
  });

  it("passes non-AI-layer findings through unchanged", () => {
    const input = [
      mkFinding({
        title: "Missing auth on GET handler",
        layer: "rules",
        id: "rules:1",
      }),
      mkFinding({
        title: "Missing auth on POST handler",
        layer: "rules",
        id: "rules:2",
      }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(2);
    expect(result.collapsedCount).toBe(0);
  });

  it("mixes AI and non-AI findings correctly", () => {
    const input = [
      mkFinding({
        title: "Rules: missing auth",
        layer: "rules",
        id: "rules:1",
      }),
      mkFinding({
        title: "Missing auth on GET handler",
        layer: "ai",
      }),
      mkFinding({
        title: "Missing auth on POST handler",
        layer: "ai",
      }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(2); // 1 rules + 1 merged AI
    expect(result.collapsedCount).toBe(1);
    const byLayer = result.findings.map((f) => f.layer).sort();
    expect(byLayer).toEqual(["ai", "rules"]);
  });

  it("handles the three-way collapse (GET/POST/PATCH)", () => {
    const input = [
      mkFinding({ title: "Service role used in GET handler without auth", evidence: [{ file: "f.ts", line: 1 }] }),
      mkFinding({ title: "Service role used in POST handler without auth", evidence: [{ file: "f.ts", line: 10 }] }),
      mkFinding({ title: "Service role used in PATCH handler without auth", evidence: [{ file: "f.ts", line: 20 }] }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(1);
    expect(result.collapsedCount).toBe(2);
    expect(result.findings[0].evidence).toHaveLength(3);
  });

  it("keeps findings from the same file+domain+title as a single group even when evidence differs", () => {
    // Simulates a real-scan scenario: 2 findings per method handler, both
    // describing the same file-level auth gap, but with different evidence
    // lines. They should collapse to one finding with merged evidence.
    const input = [
      mkFinding({
        title: "No auth check on GET /api/public/reservation/[id]",
        evidence: [{ file: "route.ts", line: 5 }],
      }),
      mkFinding({
        title: "No auth check on POST /api/public/reservation/[id]",
        evidence: [{ file: "route.ts", line: 25 }],
      }),
      mkFinding({
        title: "No auth check on PATCH /api/public/reservation/[id]",
        evidence: [{ file: "route.ts", line: 45 }],
      }),
      mkFinding({
        title: "No auth check on DELETE /api/public/reservation/[id]",
        evidence: [{ file: "route.ts", line: 65 }],
      }),
    ];
    const result = dedupAIFindings(input);
    expect(result.findings).toHaveLength(1);
    expect(result.collapsedCount).toBe(3);
    expect(result.findings[0].evidence).toHaveLength(4);
  });

  it("returns an empty result when given no findings", () => {
    const result = dedupAIFindings([]);
    expect(result.findings).toHaveLength(0);
    expect(result.collapsedCount).toBe(0);
  });

  describe("tag-based clustering", () => {
    it("collapses IDOR findings with diverse phrasings on the same file+domain", () => {
      // Real phrasing diversity observed on a production Next.js scan corpus
      const input = [
        mkFinding({ title: "IDOR in PATCH: contact update not scoped to graduate_id from URL" }),
        mkFinding({ title: "IDOR in DELETE: contact deletion not scoped to graduate_id from URL" }),
        mkFinding({ title: "PATCH handler ignores route parameter [id]; contactId not scoped to graduate" }),
        mkFinding({ title: "IDOR: Contact updated without verifying ownership" }),
      ];
      const result = dedupAIFindings(input);
      expect(result.findings).toHaveLength(1);
      expect(result.collapsedCount).toBe(3);
    });

    it("collapses rate-limit findings with diverse phrasings", () => {
      const input = [
        mkFinding({ title: "No rate limiting on invitation creation or resend actions", domain: "logging-monitoring" }),
        mkFinding({ title: "No rate limiting on invitation creation and resend — email abuse vector", domain: "logging-monitoring" }),
      ];
      const result = dedupAIFindings(input);
      expect(result.findings).toHaveLength(1);
      expect(result.collapsedCount).toBe(1);
    });

    it("collapses error-leak findings with diverse phrasings", () => {
      const input = [
        mkFinding({ title: "Raw Supabase error messages returned to the client", domain: "logging-monitoring" }),
        mkFinding({ title: "Raw database error messages exposed in HTTP responses", domain: "logging-monitoring" }),
        mkFinding({ title: "Internal database error messages forwarded directly to API clients", domain: "logging-monitoring" }),
      ];
      const result = dedupAIFindings(input);
      expect(result.findings).toHaveLength(1);
      expect(result.collapsedCount).toBe(2);
    });

    it("does NOT merge different issue tags on the same file", () => {
      // Real case: both input-injection domain but different issue types.
      // Neither matches a narrow tag, so they fall back to literal matching
      // and stay separate because their normalized titles differ.
      const input = [
        mkFinding({
          title: "Unvalidated `sortBy` parameter passed directly to `.order()` query",
          domain: "input-injection",
        }),
        mkFinding({
          title: "Unbounded `page` and `limit` parameters allow excessive data retrieval",
          domain: "input-injection",
        }),
      ];
      const result = dedupAIFindings(input);
      expect(result.findings).toHaveLength(2);
      expect(result.collapsedCount).toBe(0);
    });

    it("does NOT merge IDOR with rate-limit in the same file", () => {
      const input = [
        mkFinding({ title: "IDOR: Missing ownership check on PATCH" }),
        mkFinding({
          title: "No rate limiting on POST endpoint",
          domain: "logging-monitoring",
        }),
      ];
      const result = dedupAIFindings(input);
      expect(result.findings).toHaveLength(2);
      expect(result.collapsedCount).toBe(0);
    });
  });
});

describe("classifyIssueTag", () => {
  it("tags IDOR by the explicit keyword", () => {
    expect(classifyIssueTag("IDOR in PATCH: contact updated without check")).toBe("idor");
  });

  it("tags IDOR by ownership keyword", () => {
    expect(classifyIssueTag("Missing ownership check on DELETE endpoint")).toBe("idor");
  });

  it("tags IDOR by 'not scoped' keyword", () => {
    expect(classifyIssueTag("contactId not scoped to graduate in URL")).toBe("idor");
  });

  it("tags rate-limit correctly", () => {
    expect(classifyIssueTag("No rate limiting on invitation creation")).toBe("rate_limit");
    expect(classifyIssueTag("Missing throttling on email send")).toBe("rate_limit");
  });

  it("tags error-leak correctly", () => {
    expect(classifyIssueTag("Raw Supabase error messages returned to the client")).toBe("error_leak");
    expect(classifyIssueTag("Verbose error responses leak stack trace")).toBe("error_leak");
  });

  it("tags csrf/origin correctly", () => {
    expect(classifyIssueTag("Origin header trusted from attacker request")).toBe("csrf_origin");
  });

  it("tags rls-bypass correctly", () => {
    expect(classifyIssueTag("Service role client used on public endpoint")).toBe("rls_bypass");
  });

  it("tags privilege escalation correctly", () => {
    expect(classifyIssueTag("Business logic bypass: is_priority can be forced via body")).toBe("privilege_escalation");
  });

  it("tags race condition correctly", () => {
    expect(classifyIssueTag("Reservation cap bypassable via race condition")).toBe("race_condition");
    expect(classifyIssueTag("TOCTOU window in booking flow")).toBe("race_condition");
  });

  it("tags auth bypass when no narrower tag applies", () => {
    expect(classifyIssueTag("Unauthenticated POST endpoint creates accounts")).toBe("auth_bypass");
  });

  it("returns 'unclassified' for titles with no known keyword", () => {
    expect(classifyIssueTag("Something weird happened here")).toBe("unclassified");
  });

  it("prefers narrower tags (IDOR) over broader ones (auth_bypass)", () => {
    // Contains both "IDOR" and "unauthenticated". IDOR wins because it's
    // higher priority in the classifier order.
    expect(classifyIssueTag("Unauthenticated IDOR: any reservation reachable")).toBe("idor");
  });
});
