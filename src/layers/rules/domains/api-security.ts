import fg from "fast-glob";
import { safeReadFile } from "../../../utils/fs.js";
import type { Finding, ProjectModel } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
  impact: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "api-security",
    severity,
    confidence: "high",
    title,
    description,
    impact,
    evidence,
    remediation,
    references: [refs.cwe, refs.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId,
    cwe: refs.cwe,
    owasp: refs.owasp,
  };
}

async function walkSourceFiles(model: ProjectModel): Promise<Array<{ file: string; source: string }>> {
  const files = await fg(["**/*.{ts,tsx,js,jsx,mjs,cjs}"], {
    cwd: model.meta.path,
    absolute: true,
    ignore: [
      "**/node_modules/**",
      "**/.next/**",
      "**/dist/**",
      "**/out/**",
      "**/build/**",
      "**/public/**",
      "**/widget-build/**",
      "**/.claude/worktrees/**",
    ],
  });
  return Promise.all(files.map(async (file) => ({ file, source: await safeReadFile(file) })));
}

const SENSITIVE_ENDPOINT_RE = /login|signin|signup|register|reset|forgot|otp|verify|password/i;

export const apiSecurityRules: SecurityRule[] = [
  {
    id: "API-001",
    domain: "api-security",
    title: "CORS wildcard combined with credentials",
    description: "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
    impact: "Your API sets CORS to allow any origin with credentials. An attacker's website can make authenticated requests to your API using your users' cookies, reading and modifying their data.",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-942" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      for (const { file, source } of files) {
        const hasWildcard = /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|['"]Access-Control-Allow-Origin['"]\s*:\s*['"]\*/.test(source);
        const hasCreds = /Access-Control-Allow-Credentials["']?\s*[:,]\s*["']true|['"]Access-Control-Allow-Credentials['"]\s*:\s*['"]true/i.test(source);
        if (!hasWildcard || !hasCreds) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!/Access-Control-Allow-Origin/.test(line)) return;
          findings.push(
            mkFinding(
              "API-001",
              "critical",
              "CORS wildcard with credentials enabled",
              "Browsers reject this combination, but some frameworks mutate the Origin header in development. The intent itself signals misconfiguration.",
              "Your API sets CORS to allow any origin with credentials. An attacker's website can make authenticated requests to your API using your users' cookies, reading and modifying their data.",
              "Allowlist specific origins. Never combine * with credentials: true.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-942" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "API-002",
    domain: "api-security",
    title: "Sensitive endpoint missing rate limit",
    description: "Auth-sensitive endpoint has no rate-limit call",
    impact: "Your authentication endpoint has no rate limiting. An attacker can try thousands of passwords per second in a brute-force attack against any user account.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-307", owasp: "A07:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const rateLimitSignals = /rateLimit|ratelimit|Upstash|express-rate-limit|rate-limiter-flexible|@vercel\/ratelimit/i;
      for (const endpoint of model.endpoints) {
        if (!SENSITIVE_ENDPOINT_RE.test(endpoint.path)) continue;
        const source = await safeReadFile(endpoint.file).catch(() => "");
        if (rateLimitSignals.test(source)) continue;
        findings.push(
          mkFinding(
            "API-002",
            "high",
            `${endpoint.path} has no rate limit`,
            "Auth endpoints without rate limits enable credential stuffing and brute force attacks.",
            "Your authentication endpoint has no rate limiting. An attacker can try thousands of passwords per second in a brute-force attack against any user account.",
            "Add an IP + account-based rate limit (e.g. @upstash/ratelimit) to auth flows.",
            [{ file: endpoint.file }],
            { cwe: "CWE-307", owasp: "A07:2021" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "API-003",
    domain: "api-security",
    title: "Mass assignment via object spread",
    description: "Request body spread directly into a database call",
    impact: "Your API spreads the entire request body into a database query. An attacker can include extra fields like 'role: admin' or 'is_verified: true' to escalate their privileges.",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-915", owasp: "A08:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /\.(insert|upsert|update)\s*\(\s*\{\s*\.\.\.\s*(body|req\.body|request\.body|data|input|payload)\b/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const m = line.match(re);
          if (!m) return;
          findings.push(
            mkFinding(
              "API-003",
              "high",
              "Request body spread into database write",
              "An attacker can set fields like `role`, `is_admin`, or `user_id` that the form never exposed.",
              "Your API spreads the entire request body into a database query. An attacker can include extra fields like 'role: admin' or 'is_verified: true' to escalate their privileges.",
              "Pick only the fields the user is allowed to set. Validate with a Zod schema and pass .parse() output.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-915", owasp: "A08:2021" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "API-004",
    domain: "api-security",
    title: "Unbounded list query",
    description: "Select query without a range() or limit() clause",
    impact: "Your API returns query results without a limit. An attacker can request all records at once, causing a slow query that exhausts your database connections or crashes the server.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-770" },
    async check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        if (endpoint.method !== "GET") continue;
        const source = await safeReadFile(endpoint.file).catch(() => "");
        if (!/\.from\s*\([^)]*\)\s*\.select/.test(source)) continue;
        if (/\.(range|limit)\s*\(/.test(source)) continue;
        findings.push(
          mkFinding(
            "API-004",
            "medium",
            `${endpoint.path} returns unbounded list`,
            "Unbounded queries can exhaust memory and enable enumeration attacks.",
            "Your API returns query results without a limit. An attacker can request all records at once, causing a slow query that exhausts your database connections or crashes the server.",
            "Add .range(from, to) or .limit(N) with server-enforced upper bounds. Paginate responses.",
            [{ file: endpoint.file }],
            { cwe: "CWE-770" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "API-005",
    domain: "api-security",
    title: "HTTP method not restricted",
    description: "Route handler exports default/ALL without method allowlist",
    impact: "Your API route handler accepts all HTTP methods without restriction. An attacker can use unexpected methods like DELETE or PUT on an endpoint that was only meant for GET.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-650" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/route.{ts,tsx,js,jsx}", "**/api/**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file).catch(() => "");
        if (!source) continue;
        if (!/export\s+(default|async function|function|const)/.test(source)) continue;
        const hasMethodExports = /export\s+(async\s+function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/.test(source);
        const hasMethodCheck = /req\.method|request\.method/.test(source);
        if (hasMethodExports || hasMethodCheck) continue;
        // Pages API routes without any method check.
        if (!/\/pages\/api\//.test(file) && !/\/api\//.test(file)) continue;
        findings.push(
          mkFinding(
            "API-005",
            "medium",
            "API handler accepts any HTTP method",
            "Handlers that don't check req.method respond to GET and POST identically, enabling CSRF against read-only endpoints.",
            "Your API route handler accepts all HTTP methods without restriction. An attacker can use unexpected methods like DELETE or PUT on an endpoint that was only meant for GET.",
            "Either export per-method handlers (GET, POST...) or return 405 for unsupported methods.",
            [{ file }],
            { cwe: "CWE-650" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "API-006",
    domain: "api-security",
    title: "GraphQL introspection enabled in production",
    description: "Apollo/Mercurius/graphql-yoga with introspection: true",
    impact: "Your GraphQL endpoint has introspection enabled in production. An attacker can query your entire API schema, discovering every query, mutation, type, and field available.",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-200" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      for (const { file, source } of files) {
        if (!/graphql|apollo|mercurius|yoga/i.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!/introspection\s*:\s*true/.test(line)) return;
          findings.push(
            mkFinding(
              "API-006",
              "medium",
              "GraphQL introspection enabled",
              "Introspection exposes your entire schema to attackers, revealing internal types and queries.",
              "Your GraphQL endpoint has introspection enabled in production. An attacker can query your entire API schema, discovering every query, mutation, type, and field available.",
              "Set `introspection: process.env.NODE_ENV !== 'production'` or disable it entirely.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-200" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "API-007",
    domain: "api-security",
    title: "HTTP method override without auth",
    description: "Allow header or X-HTTP-Method-Override honoring body method",
    impact: "Your API honors HTTP method override headers without auth checks. An attacker can send a POST request with an override header to execute a DELETE, bypassing method-level protections.",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "generic-web"],
    references: { cwe: "CWE-650" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /X-HTTP-Method-Override|methodOverride\s*\(|body\s*\.\s*_method|body\[["']_method["']\]/i;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!re.test(line)) return;
          findings.push(
            mkFinding(
              "API-007",
              "medium",
              "HTTP method override accepted",
              "Method override lets a POST be treated as DELETE, bypassing browser CSRF protections that only apply to unsafe methods.",
              "Your API honors HTTP method override headers without auth checks. An attacker can send a POST request with an override header to execute a DELETE, bypassing method-level protections.",
              "Remove method override middleware and rely on standard REST verbs.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-650" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "API-008",
    domain: "api-security",
    title: "CSRF token missing on cookie-auth route",
    description: "Cookie-authenticated mutation has no CSRF check",
    impact: "Your cookie-authenticated mutation endpoint has no CSRF token. An attacker can create a page that submits a form to your API using the victim's cookies, performing actions on their behalf.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-352", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        if (!["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method)) continue;
        const source = await safeReadFile(endpoint.file).catch(() => "");
        // Only flag cookie-auth (not JSON bearer-token auth).
        const usesCookies = /cookies\s*\(|req\.cookies|request\.cookies|Set-Cookie|createServerClient/.test(source);
        if (!usesCookies) continue;
        const hasCsrf = /csrf|X-Csrf|sameSite\s*:\s*["'](strict|lax)["']/i.test(source);
        if (hasCsrf) continue;
        findings.push(
          mkFinding(
            "API-008",
            "high",
            `${endpoint.method} ${endpoint.path} has cookie auth without CSRF protection`,
            "Cookie-authenticated mutations are exploitable via CSRF if the endpoint accepts simple form-encoded requests.",
            "Your cookie-authenticated mutation endpoint has no CSRF token. An attacker can create a page that submits a form to your API using the victim's cookies, performing actions on their behalf.",
            "Require a CSRF token header, verify Origin, or set SameSite=Strict on the session cookie.",
            [{ file: endpoint.file }],
            { cwe: "CWE-352", owasp: "A01:2021" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "API-009",
    domain: "api-security",
    title: "Raw request body returned in error",
    description: "catch block returns the request body or full error object",
    impact: "Your API returns the raw request body or full error stack in error responses. An attacker can send crafted payloads to probe your internal logic and discover implementation details.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-209" },
    async check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const rawErrorRe = /(?:NextResponse\.json|Response\.json|JSON\.stringify)\s*\(\s*(err|error|e)\b/;
          if (!rawErrorRe.test(line)) return;
          if (/\.message/.test(line)) return;
          findings.push(
            mkFinding(
              "API-009",
              "medium",
              "Raw error object returned to client",
              "Serializing the entire error object leaks internal state: SQL hints, stack traces, config values.",
              "Your API returns the raw request body or full error stack in error responses. An attacker can send crafted payloads to probe your internal logic and discover implementation details.",
              "Return only `{ error: 'generic message', id: errorId }` and log the full error server-side.",
              [{ file: endpoint.file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-209" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "API-010",
    domain: "api-security",
    title: "Dynamic require/import with user input",
    description: "require() or dynamic import() argument derived from request data",
    impact: "Your API uses require() or dynamic import() with a path derived from user input. An attacker can load arbitrary modules on your server, potentially executing system commands.",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-94" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /(require|import)\s*\(\s*(req\.|request\.|params\.|searchParams|body\.|query\.)/;
      const testFileRe = /(^|\/)(__tests__|__mocks__|tests?|specs?)\/|\.(test|spec)\.[jt]sx?$|(^|\/)(scripts|build)\//;
      for (const { file, source } of files) {
        if (testFileRe.test(file)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!re.test(line)) return;
          findings.push(
            mkFinding(
              "API-010",
              "critical",
              "Dynamic import from request input",
              "Loading modules from user input is a code injection primitive.",
              "Your API uses require() or dynamic import() with a path derived from user input. An attacker can load arbitrary modules on your server, potentially executing system commands.",
              "Resolve imports from an allowlist of module names, never from a raw request value.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-94" },
            ),
          );
        });
      }
      return findings;
    },
  },
];
