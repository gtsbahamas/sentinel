import { zodToJsonSchema } from "zod-to-json-schema";
import { AIFindingSchema } from "./schema.js";
import type { ProjectModel, ApiEndpoint } from "../../model/types.js";
import type { ToolDefinition } from "./providers/base.js";

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

export function buildProjectSummary(model: ProjectModel): string {
  const { meta, routes, endpoints, dataModels, authFlows, dependencies, infra } = model;
  const routesShown = routes.slice(0, 50);
  const overflow = routes.length > 50 ? `\n  ... and ${routes.length - 50} more` : "";
  const apiCount = routes.filter((r) => r.isApi).length;
  const relevantDeps = dependencies.filter((d) => SECURITY_RELEVANT_DEPS.has(d.name));
  const headerKeys = Object.keys(infra.securityHeaders);

  return `PROJECT: ${meta.name}
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
}

export interface AdjacentFile {
  path: string;
  content: string;
}

export function buildEndpointPrompt(
  endpoint: ApiEndpoint,
  handlerSource: string,
  adjacentFiles: AdjacentFile[],
): string {
  const adjacentSection =
    adjacentFiles.length > 0
      ? `\n\nADJACENT FILES (imported helpers):\n${adjacentFiles
          .map((f) => `FILE: ${f.path}\n\`\`\`typescript\n${f.content}\n\`\`\``)
          .join("\n\n")}`
      : "";

  const serviceRoleNote = endpoint.usesServiceRole ? "YES (bypasses RLS!)" : "no";

  return `ENDPOINT: ${endpoint.method} ${endpoint.path}
FILE: ${endpoint.file}
AUTH CHECK: ${endpoint.hasAuthCheck ? "present" : "absent"}
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

export const REPORT_FINDINGS_TOOL: ToolDefinition = {
  name: "report_findings",
  description: "Report security findings discovered in the code under review. Call once per response with the complete list of findings (possibly empty).",
  schema: {
    type: "object",
    properties: {
      findings: {
        type: "array",
        items: zodToJsonSchema(AIFindingSchema, { target: "openApi3" }),
      },
    },
    required: ["findings"],
    additionalProperties: false,
  },
};
