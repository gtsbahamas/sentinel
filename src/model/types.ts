export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Confidence = "confirmed" | "high" | "medium" | "low";

export type Layer = "rules" | "ai" | "probe";

export type StackProfile = "nextjs-supabase" | "react-vite-supabase" | "generic-web";

export type SecurityDomain =
  | "secrets-exposure"
  | "input-injection"
  | "auth-access-control"
  | "file-upload"
  | "api-security"
  | "cryptography"
  | "supply-chain"
  | "infrastructure"
  | "business-logic"
  | "logging-monitoring";

export interface Evidence {
  file: string;
  line?: number;
  column?: number;
  snippet?: string;
  context?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  domain: SecurityDomain;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  evidence: Evidence[];
  remediation: string;
  references: string[];
  layer: Layer;
  cwe?: string;
  owasp?: string;
  ruleId?: string;
}

export interface Route {
  path: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD" | "ALL";
  file: string;
  isApi: boolean;
  hasAuthCheck: boolean;
  paramNames: string[];
}

export interface ApiEndpoint {
  path: string;
  method: Route["method"];
  file: string;
  handlerName?: string;
  hasValidation: boolean;
  validationLibrary?: "zod" | "yup" | "joi" | null;
  hasAuthCheck: boolean;
  usesServiceRole: boolean;
}

export interface UploadHandler {
  file: string;
  line: number;
  acceptsMultipart: boolean;
  hasMimeValidation: boolean;
  hasSizeLimit: boolean;
  usesUserFilename: boolean;
  storageDestination: "supabase" | "s3" | "local" | "other" | null;
}

export interface AuthFlow {
  type: "signup" | "login" | "oauth" | "magic-link" | "jwt-refresh";
  file: string;
  provider?: string;
}

export interface DataModel {
  name: string;
  source: "supabase" | "drizzle" | "prisma" | "other";
  hasRls: boolean | null;
  rlsPolicies: string[];
}

export interface Dependency {
  name: string;
  version: string;
  type: "production" | "dev" | "peer" | "optional";
}

export interface EnvVar {
  name: string;
  clientExposed: boolean;
  referencedIn: string[];
  inExample: boolean;
}

export interface AssetRef {
  path: string;
  publiclyServed: boolean;
  sizeBytes: number;
}

export interface ProjectMeta {
  name: string;
  path: string;
  stack: StackProfile;
  packageManager: "pnpm" | "npm" | "yarn";
  language: "typescript" | "javascript";
  framework: string;
  deployTarget: string | null;
}

export interface InfraConfig {
  // Next.js config file (next.config.{js,mjs,ts}) contents if present.
  nextConfig: { file: string; source: string } | null;
  // Middleware file contents if present.
  middleware: { file: string; source: string } | null;
  // vercel.json contents if present.
  vercelConfig: { file: string; source: string } | null;
  // supabase/config.toml contents if present.
  supabaseConfig: { file: string; source: string } | null;
  // Map of security header name (lowercased) → array of { source file, value }.
  // Collected across next.config headers(), middleware response headers,
  // and vercel.json headers.
  securityHeaders: Record<string, Array<{ file: string; value: string }>>;
}

export interface ProjectModel {
  meta: ProjectMeta;
  routes: Route[];
  endpoints: ApiEndpoint[];
  fileUploads: UploadHandler[];
  authFlows: AuthFlow[];
  dataModels: DataModel[];
  dependencies: Dependency[];
  envVars: EnvVar[];
  staticAssets: AssetRef[];
  infra: InfraConfig;
  findings: Finding[];
}

// ============================================================================
// AI Layer
// ============================================================================

export interface AIConfig {
  enabled: boolean;
  provider: "anthropic" | "openai" | "mock";
  model: string;
  deep: boolean;
  maxCostUsd: number;
  maxTokensPerEndpoint: number;
  concurrency: number;
  dryRun: boolean;
  // See src/config.ts for documentation.
  magicLinkRoutes: string[];
}

export interface AIUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  estimatedCostUsd: number;
}

export interface StageARiskSummary {
  projectRisks: Array<{
    domain: SecurityDomain;
    description: string;
    affectedEndpoints: string[];
    severity: Severity;
  }>;
  priorityOrder: string[];
}

export interface AIError {
  kind: "provider" | "parse" | "budget" | "context";
  message: string;
  endpoint?: string;
}

export interface AIRunResult {
  findings: Finding[];
  usage: AIUsage;
  stageA: StageARiskSummary | null;
  errors: AIError[];
  budgetExhausted: boolean;
  endpointsAnalyzed: number;
  endpointsSkipped: number;
  // Count of raw AI findings collapsed into their canonical duplicate.
  // See src/layers/ai/dedup.ts for the grouping rule.
  findingsCollapsed: number;
  // Count of findings whose severity was capped by the magic-link pass.
  // See src/layers/ai/magic-link.ts for the cap rule.
  magicLinkCapped: number;
  durationMs: number;
}

// ============================================================================
// Probe Layer
// ============================================================================

export type AggressionLevel = "passive" | "standard" | "intrusive";

export interface ProbeConfig {
  enabled: boolean;
  level: AggressionLevel;
  targetUrl: string | null;
  requestCaps: {
    passive: number;
    standard: number;
    intrusive: number;
  };
  requestsPerSecond: number;
  timeoutMs: number;
  allowPublicHosts: boolean;
  allowInternalNetwork: boolean;
  denyHosts: string[];
  logDir: string;
}

export interface ProbeAuthorizationEntry {
  targetOrigin: string;
  level: "passive" | "standard";
  grantedAt: string;
  expiresAt: string;
  scopeNote: string;
}

export interface ProbeTarget {
  kind: "endpoint" | "static-resource" | "baseline";
  url: string;
  method?: Route["method"];
  auth?: "required" | "unauthenticated" | "unknown";
  fromLayer: Layer | "recon";
  fromFindingId?: string;
  inputs?: ProbeTargetInput[];
}

export interface ProbeTargetInput {
  name: string;
  in: "query" | "body" | "header" | "path";
  type: "string" | "number" | "boolean" | "uuid" | "unknown";
  exampleValue?: string | number | boolean;
}

export interface ProbeEvidence {
  requestId: string;
  checkId: string;
  aggressionLevel: AggressionLevel;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    bodyPreview?: string;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    bodyPreview: string;
    timingMs: number;
  };
}

export interface ProbeFinding extends Omit<Finding, "evidence"> {
  evidence: Evidence[];
  probeEvidence: ProbeEvidence;
  confirms?: string;
  refutes?: string;
}

export interface ProbeError {
  kind:
    | "target-unreachable"
    | "auth-expired"
    | "rate-limited-by-target"
    | "cleanup-failed"
    | "check-error"
    | "cap-exceeded";
  message: string;
  checkId?: string;
  targetUrl?: string;
}

export interface ProbeRunResult {
  findings: ProbeFinding[];
  confirmedFindingIds: string[];
  refutedFindingIds: string[];
  usedRequests: number;
  requestCap: number;
  aggressionLevel: AggressionLevel;
  targetOrigin: string;
  errors: ProbeError[];
  cleanupObligationsExecuted: number;
  cleanupObligationsFailed: number;
  cleanupFailures: Array<{ obligation: string; error: string }>;
  probeLogPath: string;
  durationMs: number;
}
