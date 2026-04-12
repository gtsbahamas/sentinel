import { describe, it, expect } from "vitest";
import { applyContextSuppressions } from "../../../src/layers/context/suppression.js";
import type { Finding } from "../../../src/model/types.js";
import type { ProjectContext } from "../../../src/layers/context/types.js";

function mkFinding(overrides: Partial<Finding> & { id: string }): Finding {
  return {
    id: overrides.id,
    domain: overrides.domain ?? "auth-access-control",
    severity: overrides.severity ?? "high",
    confidence: overrides.confidence ?? "high",
    title: overrides.title ?? "Test finding",
    description: overrides.description ?? "Test description",
    evidence: overrides.evidence ?? [{ file: "src/app/api/route.ts", line: 10 }],
    remediation: overrides.remediation ?? "Fix it",
    references: overrides.references ?? [],
    layer: overrides.layer ?? "rules",
    ruleId: overrides.ruleId,
  };
}

const CTX: ProjectContext = {
  tenancy: "single-org",
  publicRoutes: [{ pattern: "/api/public/**", reason: "magic-link" }],
  validation: { library: "zod", schemaLocations: [], importedByRoutes: true },
  migrations: { rlsStrategy: "dedicated-file", rlsFile: "supabase/migrations/00003.sql" },
  framework: { routeHandlersServerOnly: true, frameworkCatchesErrors: true, serverOnlyImportGuard: false },
  excludedPaths: ["scripts/"],
  auth: { defaultClient: "anon", roleModel: ["admin"] },
  deployment: { platform: "vercel", platformHandles: ["hsts"] },
  delegations: [{ provider: "supabase", responsibility: "OAuth state verification" }],
  version: 1,
  generatedAt: "2026-04-12T00:00:00Z",
  generatedBy: "auto",
  confidence: {},
};

describe("applyContextSuppressions", () => {
  it("returns all findings when context is null", () => {
    const findings: Finding[] = [
      mkFinding({ id: "f1", ruleId: "AUTH-001", title: "POST /api/public/reservation has no auth check" }),
      mkFinding({ id: "f2", ruleId: "LOG-005" }),
    ];
    const result = applyContextSuppressions(findings, null);
    expect(result).toHaveLength(2);
    expect(result).toEqual(findings);
  });

  it("suppresses AUTH-001 on public routes", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "AUTH-001",
      title: "POST /api/public/reservation has no auth check",
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(0);
  });

  it("keeps AUTH-001 on non-public routes", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "AUTH-001",
      title: "POST /api/admin/users has no auth check",
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("f1");
  });

  it("suppresses findings in excluded paths", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "SOME-001",
      title: "Some finding in scripts",
      evidence: [{ file: "scripts/seed.ts", line: 5 }],
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(0);
  });

  it("keeps findings outside excluded paths", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "SOME-001",
      title: "Some finding in src",
      evidence: [{ file: "src/app/api/route.ts", line: 5 }],
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(1);
  });

  it("downgrades LOG-005 to info when framework catches errors", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "LOG-005",
      severity: "high",
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(1);
    expect(result[0].severity).toBe("info");
  });

  it("does not downgrade LOG-005 when framework does not catch errors", () => {
    const ctx: ProjectContext = {
      ...CTX,
      framework: { ...CTX.framework, frameworkCatchesErrors: false },
    };
    const finding = mkFinding({
      id: "f1",
      ruleId: "LOG-005",
      severity: "high",
    });
    const result = applyContextSuppressions([finding], ctx);
    expect(result).toHaveLength(1);
    expect(result[0].severity).toBe("high");
  });

  it("suppresses probe HSTS findings when platform handles it", () => {
    const finding = mkFinding({
      id: "f1",
      title: "Missing strict-transport-security header",
      layer: "probe",
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(0);
  });

  it("keeps HSTS finding when platform does not handle it", () => {
    const ctx: ProjectContext = {
      ...CTX,
      deployment: { platform: "vercel", platformHandles: [] },
    };
    const finding = mkFinding({
      id: "f1",
      title: "Missing strict-transport-security header",
      layer: "probe",
    });
    const result = applyContextSuppressions([finding], ctx);
    expect(result).toHaveLength(1);
  });

  it("suppresses AUTH-010 when OAuth state verification is delegated", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "AUTH-010",
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(0);
  });

  it("keeps AUTH-010 when OAuth state verification is not delegated", () => {
    const ctx: ProjectContext = {
      ...CTX,
      delegations: [{ provider: "other", responsibility: "something else" }],
    };
    const finding = mkFinding({
      id: "f1",
      ruleId: "AUTH-010",
    });
    const result = applyContextSuppressions([finding], ctx);
    expect(result).toHaveLength(1);
  });

  it("suppresses INFRA-010 unconditionally", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "INFRA-010",
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(0);
  });

  it("downgrades SECRETS-008 to info", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "SECRETS-008",
      severity: "medium",
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(1);
    expect(result[0].severity).toBe("info");
  });

  it("passes through unaffected findings unchanged", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "SOME-UNRELATED-RULE",
      severity: "critical",
      title: "Critical unrelated finding",
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(finding);
  });

  it("handles empty findings array", () => {
    const result = applyContextSuppressions([], CTX);
    expect(result).toHaveLength(0);
  });

  it("handles finding with no evidence (empty array)", () => {
    const finding = mkFinding({
      id: "f1",
      ruleId: "SOME-001",
      evidence: [],
    });
    const result = applyContextSuppressions([finding], CTX);
    expect(result).toHaveLength(1);
  });
});
