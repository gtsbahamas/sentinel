import { zodToJsonSchema } from "zod-to-json-schema";
import { minimatch } from "minimatch";
import { AIFindingSchema } from "./schema.js";
import { MAGIC_LINK_PROMPT_PREFIX } from "./magic-link.js";
import type { ProjectModel, ApiEndpoint } from "../../model/types.js";
import type { ToolDefinition } from "./providers/base.js";
import type { ProjectContext } from "../context/types.js";

export const SYSTEM_PREAMBLE = `You are a senior application security engineer analyzing source code.
Your job is to identify REAL security vulnerabilities — not theoretical risks.
Focus on: business logic flaws, authorization bypasses, IDOR, injection, unsafe flow composition, missing validation, unsafe defaults.
Be conservative: prefer "no finding" over a low-confidence guess.
Only report issues where you can cite specific file+line evidence from the code shown.
Cap your confidence at "high" — you are a static analyzer, not a runtime prover.`;

const SECURITY_RELEVANT_DEPS = new Set([
  "@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs",
  "next-auth", "jsonwebtoken", "iron-session", "bcrypt", "bcryptjs", "argon2",
  "cookie", "cookie-signature", "helmet", "express", "fastify", "hono",
  "zod", "yup", "joi", "validator", "dompurify", "xss",
]);

export function buildProjectSummary(model: ProjectModel, context?: ProjectContext | null): string {
  const { meta, routes, endpoints, dataModels, authFlows, dependencies, infra } = model;
  const routesShown = routes.slice(0, 50);
  const overflow = routes.length > 50 ? `\n  ... and ${routes.length - 50} more` : "";
  const apiCount = routes.filter((r) => r.isApi).length;
  const relevantDeps = dependencies.filter((d) => SECURITY_RELEVANT_DEPS.has(d.name));
  const headerKeys = Object.keys(infra.securityHeaders);

  const baseSummary = `PROJECT: ${meta.name}
STACK: ${meta.stack} · ${meta.framework} · ${meta.language}

ROUTES (${routes.length} total, ${apiCount} API):
${routesShown.map((r) => `  ${r.method} ${r.path} → ${r.file} (auth: ${r.hasAuthCheck})`).join("\n")}${overflow}

ENDPOINTS: ${endpoints.length}

DATA MODELS:
${dataModels.map((m) => `  ${m.name} (${m.source}, RLS: ${m.hasRls})`).join("\n") || "  (none detected)"}

AUTH FLOWS:
${authFlows.map((a) => `  ${a.type} in ${a.file}`).join("\n") || "  (none detected)"}

SECURITY-RELEVANT DEPENDENCIES:
${relevantDeps.map((d) => `  ${d.name}@${d.version}`).join("\n") || "  (none detected)"}

INFRA:
  Security headers present: ${headerKeys.length > 0 ? headerKeys.join(", ") : "none"}
  Middleware: ${infra.middleware ? "present" : "absent"}
  Supabase config: ${infra.supabaseConfig ? "present" : "absent"}`;

  const contextSection = context ? `

ARCHITECTURE CONTEXT:
  Tenancy: ${context.tenancy}
  Auth: ${context.auth.defaultClient} client, roles: ${context.auth.roleModel.join(", ") || "none detected"}
  Validation: ${context.validation.library !== "none" ? `${context.validation.library} schemas${context.validation.importedByRoutes ? " (imported by routes from " + context.validation.schemaLocations.join(", ") + ")" : ""}` : "none"}
  RLS: ${context.migrations.rlsStrategy}${context.migrations.rlsFile ? ` (${context.migrations.rlsFile})` : ""}
  Deployment: ${context.deployment.platform}${context.deployment.platformHandles.length > 0 ? ` (handles: ${context.deployment.platformHandles.join(", ")})` : ""}
  Intentionally public routes:
${context.publicRoutes.map((r) => `    ${r.pattern} (${r.reason})`).join("\n") || "    none"}
  Security delegated to third parties:
${context.delegations.map((d) => `    ${d.provider}: ${d.responsibility}${d.mechanism ? ` via ${d.mechanism}` : ""}`).join("\n") || "    none"}
  Non-deployed paths: ${context.excludedPaths.join(", ") || "none"}

IMPORTANT: Use this architecture context to avoid false positives. Do NOT flag:
- Public routes listed above as missing auth (they are intentionally unauthenticated)
- Security responsibilities delegated to third parties (the provider handles it)
- Files in non-deployed paths (scripts, seeds, tests — they don't run in production)` : "";

  return baseSummary + contextSection;
}

export interface AdjacentFile {
  path: string;
  content: string;
}

type DelegationMatch =
  | { matched: true; delegation: ProjectContext["delegations"][number] }
  | { matched: false };

function findDelegationFor(
  endpoint: ApiEndpoint,
  context: ProjectContext | null | undefined,
  projectRoot: string | null | undefined,
): DelegationMatch {
  if (!context) return { matched: false };
  // Normalize the endpoint file to a project-relative path so globs like
  // `src/app/api/public/reservation/**` match consistently.
  let relPath = endpoint.file;
  if (projectRoot && relPath.startsWith(projectRoot)) {
    relPath = relPath.slice(projectRoot.length).replace(/^\/+/, "");
  }
  for (const d of context.delegations) {
    if (!d.appliesTo || d.appliesTo.length === 0) continue;
    for (const pattern of d.appliesTo) {
      if (minimatch(relPath, pattern) || relPath.endsWith(pattern) || relPath === pattern) {
        return { matched: true, delegation: d };
      }
    }
  }
  return { matched: false };
}

export function buildEndpointPrompt(
  endpoint: ApiEndpoint,
  handlerSource: string,
  adjacentFiles: AdjacentFile[],
  isMagicLink = false,
  context?: ProjectContext | null,
  projectRoot?: string | null,
): string {
  const adjacentSection =
    adjacentFiles.length > 0
      ? `\n\nADJACENT FILES (imported helpers):\n${adjacentFiles
          .map((f) => `FILE: ${f.path}\n\`\`\`typescript\n${f.content}\n\`\`\``)
          .join("\n\n")}`
      : "";

  const serviceRoleNote = endpoint.usesServiceRole ? "YES (bypasses RLS!)" : "no";

  const prefix = isMagicLink ? MAGIC_LINK_PROMPT_PREFIX : "";

  const match = findDelegationFor(endpoint, context, projectRoot);
  const delegationNote = match.matched
    ? `\n\nAUTH DELEGATION (applies to this endpoint):
This endpoint delegates authentication to \`${match.delegation.mechanism ?? match.delegation.responsibility}\` (${match.delegation.provider}).
If the handler calls \`${match.delegation.mechanism ?? "the delegated verifier"}\` (directly or via a helper) and rejects requests on failure, treat that as equivalent to session-based auth. Do NOT report this endpoint as "missing auth check" or "IDOR / no ownership check" on the basis of a missing \`getUser()\`-style call.
Only flag this endpoint if you can point at a specific bypass of the delegated verifier, or a control-flow path where the verifier result is ignored.\n`
    : "";

  return `${prefix}ENDPOINT: ${endpoint.method} ${endpoint.path}
FILE: ${endpoint.file}
AUTH CHECK: ${endpoint.hasAuthCheck ? "present" : "absent"}${delegationNote}
VALIDATION: ${endpoint.validationLibrary ?? "none"}
SERVICE ROLE: ${serviceRoleNote}

HANDLER CODE:
\`\`\`typescript
${handlerSource}
\`\`\`${adjacentSection}

Analyze this endpoint for security vulnerabilities. Consider:
- Authorization bypass (missing or weak auth check)
- IDOR / insecure direct object reference (user-controlled IDs reaching queries without ownership check)
- Input validation gaps (data reaching DB/filesystem/shell unvalidated)
- Secrets exposure (env vars leaking to client, hardcoded keys)
- Unsafe defaults (service role used when user role would suffice)
- Missing rate limiting on sensitive actions
- Information disclosure in error responses

For EACH finding, call the \`report_findings\` tool.
If the endpoint has no issues, call it with an empty findings array.

Each finding MUST have a \`ruleId\` in the format \`AI-<CATEGORY>-<NNN>\`
where CATEGORY is UPPERCASE letters (e.g., AUTH, IDOR, INJECT, CRYPTO, UPLOAD,
RATELIMIT, INFO) and NNN is a 3-digit number (001, 002, ...). Pick CATEGORY based
on the domain field. Examples: AI-AUTH-001, AI-IDOR-002, AI-INJECT-001.

SEVERITY DISCIPLINE (non-negotiable):
- Reserve "critical" for findings where your \`reasoning\` field describes a
  specific, reproducible exploit path an attacker could execute today — who
  they are, what request they send, what they get back. "No auth check" alone
  is NOT a critical exploit path; it is a precondition. A real exploit path
  names the attacker, their input, and the resulting damage.
- Your \`confidence\` field constrains your \`severity\`:
    * confidence "high"   → severity may be up to "critical"
    * confidence "medium" → severity may be up to "high"
    * confidence "low"    → severity may be up to "medium"
  We enforce this cap after you respond. Assigning "critical" with non-"high"
  confidence wastes output tokens.
- When you are tempted to mark something "critical" because the surface looks
  risky but you cannot cite the exploit, use "high" with confidence "medium"
  or "medium" with confidence "high" instead. Be specific, not loud.

Do NOT report:
- Theoretical issues with no concrete evidence in the code above
- Issues where "depends on configuration" is the main caveat
- Things static rules would catch (hardcoded secrets, obvious SQL concat)`;
}

export function buildStageAPrompt(model: ProjectModel): string {
  const summary = buildProjectSummary(model);
  return `You are doing a project-wide security triage on a ${model.meta.stack} project.

${summary}

Identify the TOP security risks in this project WITHOUT analyzing individual files yet. Use only the summary above.

For EACH risk, call \`report_project_risks\` with:
- The affected domain
- A description of the risk pattern
- Which endpoints are most likely affected (cite paths from the route list)
- Severity estimate

Then produce a priority order: list the endpoint paths you'd analyze first, most-risky to least-risky. Include EVERY API endpoint in the list.`;
}

// Keywords that are rejected by Anthropic's JSON Schema draft 2020-12 validator
// and/or OpenAI's json_schema strict mode. Zod re-validates the parsed response,
// so stripping these from the advisory schema is lossless.
const UNSUPPORTED_KEYWORDS = new Set([
  "pattern",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "minItems",
  "maxItems",
  "uniqueItems",
  "format",
  "multipleOf",
]);

function toNullable(prop: Record<string, unknown>): Record<string, unknown> {
  const t = prop.type;
  if (typeof t === "string") return { ...prop, type: [t, "null"] };
  if (Array.isArray(t) && !t.includes("null")) return { ...prop, type: [...t, "null"] };
  return prop;
}

// 1. Drops keywords rejected by Anthropic's JSON Schema draft 2020-12 validator
//    and/or OpenAI's json_schema strict mode.
// 2. For object nodes, moves all properties into `required` and rewrites
//    previously-optional fields as nullable — OpenAI strict requires every
//    property listed in `required`; Anthropic accepts this form as well.
// Zod re-validates the parsed response, so this lossy transform stays lossless
// against the ground-truth AIFindingSchema.
function sanitizeSchema(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(sanitizeSchema);
  if (!node || typeof node !== "object") return node;

  const obj = node as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (UNSUPPORTED_KEYWORDS.has(k)) continue;
    out[k] = sanitizeSchema(v);
  }

  if (out.type === "object" && out.properties && typeof out.properties === "object") {
    const props = out.properties as Record<string, Record<string, unknown>>;
    const existingRequired = Array.isArray(out.required) ? (out.required as string[]) : [];
    const allKeys = Object.keys(props);
    const optional = allKeys.filter((k) => !existingRequired.includes(k));
    for (const k of optional) {
      props[k] = toNullable(props[k]);
    }
    out.required = allKeys;
  }

  return out;
}

export const REPORT_FINDINGS_TOOL: ToolDefinition = {
  name: "report_findings",
  description: "Report security findings discovered in the code under review. Call once per response with the complete list of findings (possibly empty).",
  schema: {
    type: "object",
    properties: {
      findings: {
        type: "array",
        items: sanitizeSchema(zodToJsonSchema(AIFindingSchema)),
      },
    },
    required: ["findings"],
    additionalProperties: false,
  },
};
