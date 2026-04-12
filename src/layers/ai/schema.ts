import { z } from "zod";
import type { Finding } from "../../model/types.js";

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

export function aiToFinding(ai: AIFinding): Finding {
  const first = ai.evidence[0];
  return {
    id: `ai:${ai.ruleId}:${first.file}:${first.line ?? 0}`,
    domain: ai.domain,
    severity: ai.severity,
    confidence: ai.confidence,
    title: ai.title,
    description: ai.description,
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
