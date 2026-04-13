import { z } from "zod";
import type { Finding, Severity } from "../../model/types.js";

export const AIFindingSchema = z.object({
  ruleId: z.string().regex(/^AI-[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3}$/),
  domain: z.enum([
    "secrets-exposure",
    "input-injection",
    "auth-access-control",
    "file-upload",
    "api-security",
    "cryptography",
    "supply-chain",
    "infrastructure",
    "business-logic",
    "logging-monitoring",
  ]),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  confidence: z.enum(["high", "medium", "low"]),
  title: z.string().min(10).max(200),
  description: z.string().min(20).max(2000),
  evidence: z
    .array(
      z.object({
        file: z.string(),
        line: z.number().int().positive().nullish(),
        snippet: z.string().max(500).nullish(),
      }),
    )
    .min(1),
  impact: z.string().min(10).max(1000).optional(),
  remediation: z.string().min(20).max(1000),
  reasoning: z.string().min(20).max(2000),
});

export type AIFinding = z.infer<typeof AIFindingSchema>;

export const StageARiskSchema = z.object({
  projectRisks: z.array(
    z.object({
      domain: AIFindingSchema.shape.domain,
      description: z.string().min(10),
      affectedEndpoints: z.array(z.string()),
      severity: AIFindingSchema.shape.severity,
    }),
  ),
  priorityOrder: z.array(z.string()),
});

// Severity ladder used by capSeverity. Lower index = more severe.
const SEVERITY_RANK: Severity[] = ["critical", "high", "medium", "low", "info"];

// Confidence-based severity cap. The AI is instructed about this in the
// prompt but we enforce it deterministically here so the output is
// well-defined regardless of what the model actually returns.
//   confidence "high"   → severity may be up to "critical"  (no cap)
//   confidence "medium" → severity may be up to "high"
//   confidence "low"    → severity may be up to "medium"
// Rationale: "critical" should mean "exploitable with reasonable
// preconditions" — an honest ceiling for lower-confidence findings
// prevents severity inflation and keeps the critical bucket trustworthy.
export function capSeverity(severity: Severity, confidence: AIFinding["confidence"]): Severity {
  const ceiling: Severity = confidence === "high" ? "critical" : confidence === "medium" ? "high" : "medium";
  const ceilingRank = SEVERITY_RANK.indexOf(ceiling);
  const currentRank = SEVERITY_RANK.indexOf(severity);
  return currentRank < ceilingRank ? ceiling : severity;
}

export function aiToFinding(ai: AIFinding): Finding {
  const first = ai.evidence[0];
  const cappedSeverity = capSeverity(ai.severity, ai.confidence);
  return {
    id: `ai:${ai.ruleId}:${first.file}:${first.line ?? 0}`,
    domain: ai.domain,
    severity: cappedSeverity,
    confidence: ai.confidence,
    title: ai.title,
    description: ai.description,
    impact: ai.impact ?? ai.description,
    evidence: ai.evidence.map((e) => ({
      file: e.file,
      line: e.line ?? undefined,
      snippet: e.snippet ?? undefined,
      context: { reasoning: ai.reasoning },
    })),
    remediation: ai.remediation,
    references: [],
    layer: "ai",
    ruleId: ai.ruleId,
  };
}
