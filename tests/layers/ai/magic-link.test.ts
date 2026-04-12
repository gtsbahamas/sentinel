import { describe, it, expect } from "vitest";
import {
  globToRegex,
  isMagicLinkPath,
  isMagicLinkEndpoint,
  applyMagicLinkSeverityCap,
  MAGIC_LINK_PROMPT_PREFIX,
} from "../../../src/layers/ai/magic-link.js";
import type { ApiEndpoint, Finding } from "../../../src/model/types.js";

function mkEndpoint(path: string, file = `/root${path}/route.ts`): ApiEndpoint {
  return {
    path,
    method: "GET",
    file,
    hasValidation: false,
    validationLibrary: null,
    hasAuthCheck: false,
    usesServiceRole: false,
  };
}

function mkFinding(overrides: Partial<Finding> & Pick<Finding, "title" | "evidence">): Finding {
  return {
    id: overrides.id ?? `ai:${overrides.title}`,
    domain: overrides.domain ?? "auth-access-control",
    severity: overrides.severity ?? "critical",
    confidence: overrides.confidence ?? "high",
    title: overrides.title,
    description: overrides.description ?? "...",
    evidence: overrides.evidence,
    remediation: overrides.remediation ?? "...",
    references: overrides.references ?? [],
    layer: overrides.layer ?? "ai",
    ruleId: overrides.ruleId ?? "AI-AUTH-001",
  };
}

describe("globToRegex", () => {
  it("matches literal paths", () => {
    const re = globToRegex("/api/reset");
    expect(re.test("/api/reset")).toBe(true);
    expect(re.test("/api/reset/x")).toBe(false);
  });

  it("matches ** for any depth", () => {
    const re = globToRegex("/api/public/**");
    expect(re.test("/api/public")).toBe(true);
    expect(re.test("/api/public/foo")).toBe(true);
    expect(re.test("/api/public/foo/bar/baz")).toBe(true);
    expect(re.test("/api/other")).toBe(false);
  });

  it("matches * for a single segment", () => {
    const re = globToRegex("/api/reset/*");
    expect(re.test("/api/reset/abc")).toBe(true);
    expect(re.test("/api/reset/abc/xyz")).toBe(false);
  });

  it("escapes regex metacharacters", () => {
    const re = globToRegex("/api/item.json");
    expect(re.test("/api/item.json")).toBe(true);
    expect(re.test("/api/itemxjson")).toBe(false);
  });

  it("is fully anchored", () => {
    const re = globToRegex("/api/public/**");
    expect(re.test("prefix/api/public/x")).toBe(false);
    expect(re.test("/api/public/x/suffix")).toBe(true);
  });
});

describe("isMagicLinkPath", () => {
  it("returns false when no patterns provided", () => {
    expect(isMagicLinkPath("/api/public/x", [])).toBe(false);
  });

  it("returns true when any pattern matches", () => {
    expect(isMagicLinkPath("/api/public/x", ["/api/reset/*", "/api/public/**"])).toBe(true);
  });

  it("returns false when nothing matches", () => {
    expect(isMagicLinkPath("/api/users", ["/api/reset/*", "/api/public/**"])).toBe(false);
  });

  it("matches [id] style Next.js paths", () => {
    expect(isMagicLinkPath("/api/public/reservation/[id]", ["/api/public/**"])).toBe(true);
  });
});

describe("isMagicLinkEndpoint", () => {
  it("matches the endpoint's declared path", () => {
    const ep = mkEndpoint("/api/public/reservation/[id]");
    expect(isMagicLinkEndpoint(ep, ["/api/public/**"])).toBe(true);
    expect(isMagicLinkEndpoint(ep, ["/api/private/**"])).toBe(false);
  });
});

describe("MAGIC_LINK_PROMPT_PREFIX", () => {
  it("mentions the access model and what NOT to flag", () => {
    expect(MAGIC_LINK_PROMPT_PREFIX).toContain("unguessable token");
    expect(MAGIC_LINK_PROMPT_PREFIX).toContain("DO NOT report");
    expect(MAGIC_LINK_PROMPT_PREFIX).toMatch(/token predictability/i);
  });

  it("ends with a clean separator so the endpoint block follows", () => {
    expect(MAGIC_LINK_PROMPT_PREFIX.endsWith("\n\n")).toBe(true);
  });
});

describe("applyMagicLinkSeverityCap", () => {
  const routes = ["/api/public/**"];
  const endpoints = [mkEndpoint("/api/public/reservation/[id]", "/root/api/public/route.ts")];

  it("returns findings unchanged when no patterns configured", () => {
    const finding = mkFinding({
      title: "IDOR: any reservation accessible",
      evidence: [{ file: "/root/api/public/route.ts", line: 10 }],
      severity: "critical",
    });
    const result = applyMagicLinkSeverityCap([finding], [], endpoints);
    expect(result.cappedCount).toBe(0);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("caps IDOR findings on magic-link endpoints at medium", () => {
    const finding = mkFinding({
      title: "IDOR: any reservation accessible by guessing ID",
      evidence: [{ file: "/root/api/public/route.ts", line: 10 }],
      severity: "critical",
    });
    const result = applyMagicLinkSeverityCap([finding], routes, endpoints);
    expect(result.cappedCount).toBe(1);
    expect(result.findings[0].severity).toBe("medium");
  });

  it("caps auth-bypass findings on magic-link endpoints at medium", () => {
    const finding = mkFinding({
      title: "Unauthenticated POST endpoint allows modification",
      evidence: [{ file: "/root/api/public/route.ts", line: 10 }],
      severity: "critical",
    });
    const result = applyMagicLinkSeverityCap([finding], routes, endpoints);
    expect(result.cappedCount).toBe(1);
    expect(result.findings[0].severity).toBe("medium");
  });

  it("does NOT cap findings whose severity is already medium or lower", () => {
    const finding = mkFinding({
      title: "IDOR-adjacent medium finding",
      evidence: [{ file: "/root/api/public/route.ts", line: 10 }],
      severity: "low",
    });
    const result = applyMagicLinkSeverityCap([finding], routes, endpoints);
    expect(result.cappedCount).toBe(0);
    expect(result.findings[0].severity).toBe("low");
  });

  it("does NOT cap findings on non-magic-link endpoints", () => {
    const finding = mkFinding({
      title: "IDOR: no ownership check on user id",
      evidence: [{ file: "/root/api/users/route.ts", line: 10 }],
      severity: "critical",
    });
    const nonMagicEndpoints = [mkEndpoint("/api/users", "/root/api/users/route.ts")];
    const result = applyMagicLinkSeverityCap([finding], routes, nonMagicEndpoints);
    expect(result.cappedCount).toBe(0);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("does NOT cap non-access-control findings on magic-link endpoints", () => {
    // Injection, PII leak, error leak, etc. should pass through unchanged
    // even when the endpoint is magic-link. Their severity is not driven
    // by the access-model distinction.
    const finding = mkFinding({
      title: "SQL injection in raw query",
      domain: "input-injection",
      evidence: [{ file: "/root/api/public/route.ts", line: 10 }],
      severity: "critical",
    });
    const result = applyMagicLinkSeverityCap([finding], routes, endpoints);
    expect(result.cappedCount).toBe(0);
    expect(result.findings[0].severity).toBe("critical");
  });

  it("does NOT cap findings in auth-access-control whose tag is neither IDOR nor auth-bypass", () => {
    // A privilege-escalation finding on a magic-link endpoint is still
    // a real issue the AI should surface — the magic-link pattern
    // doesn't imply anyone can set `is_admin`.
    const finding = mkFinding({
      title: "Privilege escalation: is_priority can be forced via body",
      evidence: [{ file: "/root/api/public/route.ts", line: 10 }],
      severity: "high",
    });
    const result = applyMagicLinkSeverityCap([finding], routes, endpoints);
    expect(result.cappedCount).toBe(0);
    expect(result.findings[0].severity).toBe("high");
  });

  it("handles a mix of capped and passthrough findings", () => {
    const findings: Finding[] = [
      mkFinding({
        title: "IDOR: any reservation accessible",
        evidence: [{ file: "/root/api/public/route.ts", line: 10 }],
        severity: "critical",
      }),
      mkFinding({
        title: "SQL injection in raw query",
        domain: "input-injection",
        evidence: [{ file: "/root/api/public/route.ts", line: 20 }],
        severity: "critical",
      }),
      mkFinding({
        title: "IDOR on a different file",
        evidence: [{ file: "/root/api/users/route.ts", line: 5 }],
        severity: "critical",
      }),
    ];
    const mixedEndpoints = [
      mkEndpoint("/api/public/reservation/[id]", "/root/api/public/route.ts"),
      mkEndpoint("/api/users", "/root/api/users/route.ts"),
    ];
    const result = applyMagicLinkSeverityCap(findings, routes, mixedEndpoints);
    expect(result.cappedCount).toBe(1);
    expect(result.findings[0].severity).toBe("medium"); // IDOR magic-link → capped
    expect(result.findings[1].severity).toBe("critical"); // SQL injection → unchanged
    expect(result.findings[2].severity).toBe("critical"); // IDOR non-magic → unchanged
  });
});
