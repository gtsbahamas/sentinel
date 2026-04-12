import { z } from "zod";

const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
const ConfidenceSchema = z.enum(["confirmed", "high", "medium", "low"]);
const AggressionLevelSchema = z.enum(["passive", "standard", "intrusive"]);

const SecurityDomainSchema = z.enum([
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
]);

export const ProbeEvidenceSchema = z.object({
  requestId: z.string(),
  checkId: z.string(),
  aggressionLevel: AggressionLevelSchema,
  request: z.object({
    method: z.string(),
    url: z.string(),
    headers: z.record(z.string()),
    bodyPreview: z.string().optional(),
  }),
  response: z.object({
    status: z.number().int(),
    headers: z.record(z.string()),
    bodyPreview: z.string(),
    timingMs: z.number(),
  }),
});

export const ProbeFindingSchema = z.object({
  id: z.string(),
  domain: SecurityDomainSchema,
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  title: z.string(),
  description: z.string(),
  evidence: z.array(
    z.object({
      file: z.string(),
      line: z.number().optional(),
      column: z.number().optional(),
      snippet: z.string().optional(),
      context: z.record(z.unknown()).optional(),
    }),
  ),
  remediation: z.string(),
  references: z.array(z.string()),
  layer: z.literal("probe"),
  cwe: z.string().optional(),
  owasp: z.string().optional(),
  ruleId: z.string().optional(),
  probeEvidence: ProbeEvidenceSchema,
  confirms: z.string().optional(),
  refutes: z.string().optional(),
});

export const ProbeAuthorizationEntrySchema = z.object({
  targetOrigin: z.string(),
  level: z.enum(["passive", "standard"]),
  grantedAt: z.string(),
  expiresAt: z.string(),
  scopeNote: z.string(),
});

export const ProbeConfigSchema = z.object({
  enabled: z.boolean().default(false),
  level: AggressionLevelSchema.default("passive"),
  targetUrl: z.string().nullable().default(null),
  requestCaps: z
    .object({
      passive: z.number().int().positive().default(500),
      standard: z.number().int().positive().default(2000),
      intrusive: z.number().int().positive().default(5000),
    })
    .default({}),
  requestsPerSecond: z.number().positive().default(10),
  timeoutMs: z.number().int().positive().default(10_000),
  allowPublicHosts: z.boolean().default(false),
  allowInternalNetwork: z.boolean().default(false),
  denyHosts: z
    .array(z.string())
    .default([
      "google.com",
      "www.google.com",
      "microsoft.com",
      "www.microsoft.com",
      "amazon.com",
      "www.amazon.com",
      "aws.amazon.com",
      "apple.com",
      "icloud.com",
      "github.com",
      "gitlab.com",
      "cloudflare.com",
      "facebook.com",
      "meta.com",
      "openai.com",
      "anthropic.com",
    ]),
  logDir: z.string().default(".sentinel/"),
});

export const PROBE_CONFIG_DEFAULTS: z.infer<typeof ProbeConfigSchema> = ProbeConfigSchema.parse({});
