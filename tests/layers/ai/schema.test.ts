import { describe, it, expect } from "vitest";
import {
  AIFindingSchema,
  StageARiskSchema,
  aiToFinding,
  capSeverity,
  type AIFinding,
} from "../../../src/layers/ai/schema.js";

const baseValid: AIFinding = {
  ruleId: "AI-IDOR-001",
  domain: "auth-access-control",
  severity: "high",
  confidence: "medium",
  title: "Missing ownership check before user update",
  description: "The PATCH handler accepts an arbitrary user id from the URL parameter and updates the row without verifying the caller owns it.",
  evidence: [{ file: "src/app/api/users/[id]/route.ts", line: 42, snippet: "await supabase.from('users').update(body).eq('id', params.id)" }],
  remediation: "Fetch the authenticated session and confirm session.user.id === params.id before updating.",
  reasoning: "The handler reads params.id directly into the .eq() filter with no ownership check. Anyone with a valid session could update any user's row.",
};

describe("AIFindingSchema", () => {
  it("accepts a valid finding", () => {
    expect(() => AIFindingSchema.parse(baseValid)).not.toThrow();
  });

  it('rejects confidence: "confirmed" (AI cap)', () => {
    expect(() => AIFindingSchema.parse({ ...baseValid, confidence: "confirmed" as never })).toThrow();
  });

  it("rejects empty evidence array", () => {
    expect(() => AIFindingSchema.parse({ ...baseValid, evidence: [] })).toThrow();
  });

  it("rejects bad ruleId format", () => {
    expect(() => AIFindingSchema.parse({ ...baseValid, ruleId: "BAD-001" })).toThrow();
    expect(() => AIFindingSchema.parse({ ...baseValid, ruleId: "AI-idor-001" })).toThrow();
    expect(() => AIFindingSchema.parse({ ...baseValid, ruleId: "AI-IDOR-1" })).toThrow();
  });

  it("rejects title shorter than 10 characters", () => {
    expect(() => AIFindingSchema.parse({ ...baseValid, title: "short" })).toThrow();
  });

  it("rejects unknown domain", () => {
    expect(() => AIFindingSchema.parse({ ...baseValid, domain: "typescript-errors" as never })).toThrow();
  });

  it("rejects reasoning shorter than 20 characters", () => {
    expect(() => AIFindingSchema.parse({ ...baseValid, reasoning: "looks bad" })).toThrow();
  });

  it('accepts confidence: "low"', () => {
    expect(() => AIFindingSchema.parse({ ...baseValid, confidence: "low" })).not.toThrow();
  });

  it("rejects unknown severity", () => {
    expect(() => AIFindingSchema.parse({ ...baseValid, severity: "catastrophic" as never })).toThrow();
  });
});

describe("aiToFinding adapter", () => {
  it("produces a Finding tagged layer: ai with stable id", () => {
    const finding = aiToFinding(baseValid);
    expect(finding.layer).toBe("ai");
    expect(finding.ruleId).toBe("AI-IDOR-001");
    expect(finding.id).toBe("ai:AI-IDOR-001:src/app/api/users/[id]/route.ts:42");
    expect(finding.severity).toBe("high");
    expect(finding.confidence).toBe("medium");
    expect(finding.domain).toBe("auth-access-control");
  });

  it("writes reasoning into evidence[0].context.reasoning", () => {
    const finding = aiToFinding(baseValid);
    expect(finding.evidence[0].context).toEqual({ reasoning: baseValid.reasoning });
  });

  it("falls back to line 0 in id when evidence.line is missing", () => {
    const noLine: AIFinding = {
      ...baseValid,
      evidence: [{ file: "src/app/api/foo/route.ts" }],
    };
    const finding = aiToFinding(noLine);
    expect(finding.id).toBe("ai:AI-IDOR-001:src/app/api/foo/route.ts:0");
  });

  it("writes reasoning into context on ALL evidence entries, not just the first", () => {
    const multi: AIFinding = {
      ...baseValid,
      evidence: [
        { file: "a.ts", line: 1 },
        { file: "b.ts", line: 2, snippet: "x" },
        { file: "c.ts" },
      ],
    };
    const finding = aiToFinding(multi);
    expect(finding.evidence).toHaveLength(3);
    for (const e of finding.evidence) {
      expect(e.context).toEqual({ reasoning: multi.reasoning });
    }
  });
});

describe("capSeverity", () => {
  it("leaves high-confidence severities unchanged at any level", () => {
    expect(capSeverity("critical", "high")).toBe("critical");
    expect(capSeverity("high", "high")).toBe("high");
    expect(capSeverity("medium", "high")).toBe("medium");
    expect(capSeverity("low", "high")).toBe("low");
    expect(capSeverity("info", "high")).toBe("info");
  });

  it("caps medium confidence at severity 'high'", () => {
    expect(capSeverity("critical", "medium")).toBe("high");
    expect(capSeverity("high", "medium")).toBe("high");
    expect(capSeverity("medium", "medium")).toBe("medium");
    expect(capSeverity("low", "medium")).toBe("low");
  });

  it("caps low confidence at severity 'medium'", () => {
    expect(capSeverity("critical", "low")).toBe("medium");
    expect(capSeverity("high", "low")).toBe("medium");
    expect(capSeverity("medium", "low")).toBe("medium");
    expect(capSeverity("low", "low")).toBe("low");
    expect(capSeverity("info", "low")).toBe("info");
  });
});

describe("aiToFinding severity cap integration", () => {
  it("downgrades critical+medium-confidence to high", () => {
    const finding = aiToFinding({ ...baseValid, severity: "critical", confidence: "medium" });
    expect(finding.severity).toBe("high");
    // Confidence itself is preserved so callers can see why the cap applied.
    expect(finding.confidence).toBe("medium");
  });

  it("downgrades critical+low-confidence to medium", () => {
    const finding = aiToFinding({ ...baseValid, severity: "critical", confidence: "low" });
    expect(finding.severity).toBe("medium");
    expect(finding.confidence).toBe("low");
  });

  it("preserves critical when confidence is high", () => {
    const finding = aiToFinding({ ...baseValid, severity: "critical", confidence: "high" });
    expect(finding.severity).toBe("critical");
  });

  it("does not raise severities that are already below the cap", () => {
    const finding = aiToFinding({ ...baseValid, severity: "low", confidence: "high" });
    expect(finding.severity).toBe("low");
  });
});

describe("StageARiskSchema", () => {
  const validRisk = {
    projectRisks: [
      {
        domain: "auth-access-control" as const,
        description: "Handlers missing ownership checks",
        affectedEndpoints: ["/api/users/[id]"],
        severity: "high" as const,
      },
    ],
    priorityOrder: ["/api/users/[id]", "/api/orders/[id]"],
  };

  it("accepts a valid risk summary", () => {
    expect(() => StageARiskSchema.parse(validRisk)).not.toThrow();
  });

  it("rejects an unknown domain in projectRisks", () => {
    expect(() =>
      StageARiskSchema.parse({
        ...validRisk,
        projectRisks: [{ ...validRisk.projectRisks[0], domain: "typescript-errors" as never }],
      }),
    ).toThrow();
  });

  it("accepts empty projectRisks and priorityOrder arrays", () => {
    expect(() => StageARiskSchema.parse({ projectRisks: [], priorityOrder: [] })).not.toThrow();
  });
});
