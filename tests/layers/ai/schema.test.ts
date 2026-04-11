import { describe, it, expect } from "vitest";
import { AIFindingSchema, aiToFinding, type AIFinding } from "../../../src/layers/ai/schema.js";

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
});
