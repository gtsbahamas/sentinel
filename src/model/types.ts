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
  findings: Finding[];
}
