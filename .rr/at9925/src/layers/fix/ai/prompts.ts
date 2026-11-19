import type { Finding } from "../../../model/types.js";

export interface PromptTemplate {
  id: string;
  system: string;
  buildUserPrompt(fileContent: string, findings: Finding[]): string;
}

const SYSTEM_BASE = `You are a security engineer applying minimal, targeted fixes to source code.
Rules:
- Make only the changes necessary to address the reported security issues.
- Do not refactor, rename, or improve unrelated code.
- Preserve all existing exports, function signatures, and module structure.
- Return ONLY the complete fixed file content with no markdown fences, no explanation, and no commentary.
- If the fix requires new imports, add them at the top of the file.`;

const INPUT_005_TEMPLATE: PromptTemplate = {
  id: "INPUT-005",
  system: SYSTEM_BASE,
  buildUserPrompt(fileContent: string, findings: Finding[]): string {
    const locations = findings
      .flatMap((f) => f.evidence)
      .map((e) => `  - ${e.file}${e.line != null ? `:${e.line}` : ""}${e.snippet ? ` — ${e.snippet}` : ""}`)
      .join("\n");

    return `Fix the following input-validation security findings in this file:

${locations}

Instructions:
1. Inspect the request handler(s) to infer the expected body shape from how fields are accessed (e.g. req.body.email, body.userId).
2. Create a Zod schema that validates those fields with appropriate types.
3. Call schema.parse(body) or schema.safeParse(body) at the top of the handler before any business logic.
4. Wrap the parse call in a try/catch (or check .success for safeParse) and return a 400 JSON response on validation failure.
5. Add \`import { z } from "zod";\` if not already present.

File content:
\`\`\`
${fileContent}
\`\`\`

Return the complete fixed file content only.`;
  },
};

// AUTH-001: Mutation endpoint without auth check.
// Adds supabase.auth.getUser() guard to POST/PUT/PATCH/DELETE handlers.
// (This template was previously mislabeled as AUTH-002; AUTH-002 is about RLS
// migrations on DB tables, not handler auth checks.)
const AUTH_001_TEMPLATE: PromptTemplate = {
  id: "AUTH-001",
  system: SYSTEM_BASE,
  buildUserPrompt(fileContent: string, findings: Finding[]): string {
    const locations = findings
      .flatMap((f) => f.evidence)
      .map((e) => `  - ${e.file}${e.line != null ? `:${e.line}` : ""}${e.snippet ? ` — ${e.snippet}` : ""}`)
      .join("\n");

    return `Fix the following authentication security findings in this file:

${locations}

Instructions:
1. Add a Supabase auth check using createRouteHandlerClient from @supabase/auth-helpers-nextjs and cookies from next/headers.
2. Call supabase.auth.getUser() at the start of the handler (before any business logic).
3. If getUser() returns an error or no user, return a 401 JSON response: { error: "Unauthorized" }.
4. Add the necessary imports if not already present:
   - \`import { createRouteHandlerClient } from "@supabase/auth-helpers-nextjs";\`
   - \`import { cookies } from "next/headers";\`
5. Do not change any other logic.

File content:
\`\`\`
${fileContent}
\`\`\`

Return the complete fixed file content only.`;
  },
};

const API_004_TEMPLATE: PromptTemplate = {
  id: "API-004",
  system: SYSTEM_BASE,
  buildUserPrompt(fileContent: string, findings: Finding[]): string {
    const locations = findings
      .flatMap((f) => f.evidence)
      .map((e) => `  - ${e.file}${e.line != null ? `:${e.line}` : ""}${e.snippet ? ` — ${e.snippet}` : ""}`)
      .join("\n");

    return `Fix the following rate-limiting security findings in this file:

${locations}

Instructions:
1. Add an in-memory rate limiter using a Map to track request counts per IP address.
2. The rate limit should allow a maximum of 60 requests per minute per IP.
3. Extract the client IP from the request (use req.headers.get("x-forwarded-for") ?? req.headers.get("x-real-ip") ?? "unknown").
4. At the start of the handler, check the rate limit and return a 429 JSON response if exceeded: { error: "Too Many Requests" }.
5. Place the rate-limit Map and cleanup logic at module scope (outside the handler function).
6. The cleanup should remove entries older than 60 seconds to prevent unbounded memory growth.
7. Do not change any other logic.

Example pattern:
\`\`\`typescript
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT = 60;
const WINDOW_MS = 60_000;

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT) return false;
  entry.count++;
  return true;
}
\`\`\`

File content:
\`\`\`
${fileContent}
\`\`\`

Return the complete fixed file content only.`;
  },
};

const TEMPLATES: PromptTemplate[] = [INPUT_005_TEMPLATE, AUTH_001_TEMPLATE, API_004_TEMPLATE];

export function getPromptTemplate(id: string): PromptTemplate | undefined {
  return TEMPLATES.find((t) => t.id === id);
}
