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
