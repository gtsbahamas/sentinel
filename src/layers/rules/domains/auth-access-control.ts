import { safeReadFile, readEnvFile, parseEnvFile } from "../../../utils/fs.js";
import fg from "fast-glob";
import { join, relative, isAbsolute } from "path";
import { minimatch } from "minimatch";
import { loadConfig, type ConventionRule } from "../../../config.js";
import { DEFAULT_EXCLUDED_SEGMENTS, isExcludedPath } from "../../recon/pattern-inference.js";
import type { Finding, ProjectModel, InferredPattern } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

// Compute the path that `match` globs are written against. Endpoint files
// are absolute on disk; conventions in `.sentinelrc.json` and inferred
// pathGlobs are project-relative, so we normalize before testing.
function relPath(projectRoot: string, file: string): string {
  if (!isAbsolute(file)) return file;
  const rel = relative(projectRoot, file);
  // On Windows minimatch wants forward slashes; this is a no-op on POSIX.
  return rel.split("\\").join("/");
}

// Test a glob with a forgiving fallback: if minimatch returns false but
// the user wrote a substring-style match (e.g. "src/app/api/admin"), fall
// back to includes() so a freshly-typed rule still does the right thing.
function pathMatches(relFile: string, glob: string): boolean {
  if (minimatch(relFile, glob)) return true;
  // Strip leading "./" or trailing slash for a forgiving substring check.
  const trimmed = glob.replace(/^\.\//, "").replace(/\/+$/, "").replace(/\/?\*\*?$/, "");
  if (trimmed && relFile.includes(trimmed)) return true;
  return false;
}

// True if `source` contains a call to `helper(` (word-boundary anchored,
// optional whitespace before the open paren). Used by both convention
// rules to detect whether the required auth helper is invoked.
function callsHelper(source: string, helper: string): boolean {
  // Escape regex metacharacters in the helper name. Identifiers usually
  // don't contain any, but defend against config typos like "auth.guard".
  const escaped = helper.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`\\b${escaped}\\s*\\(`).test(source);
}

const SESSION_SECRET_KEYS = [
  "SESSION_SECRET",
  "JWT_SECRET",
  "NEXTAUTH_SECRET",
  "AUTH_SECRET",
  "COOKIE_SECRET",
  "IRON_SESSION_PASSWORD",
];

const ENV_CANDIDATES = [".env", ".env.local", ".env.production", ".env.development"];

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
    domain: "auth-access-control",
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

export const authAccessControlRules: SecurityRule[] = [
  {
    id: "AUTH-001",
    domain: "auth-access-control",
    title: "Mutation endpoint without auth check",
    description: "POST/PUT/PATCH/DELETE handler has no auth detection",
    impact: "Your API endpoint handles mutations (create, update, delete) without verifying who is making the request. Any anonymous user or bot can call this endpoint and modify your data.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-862", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        if (["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method) && !endpoint.hasAuthCheck) {
          // Respect an explicit suppression pragma so intentional public
          // endpoints (e.g., embeddable widget APIs) don't generate noise.
          const source = await safeReadFile(endpoint.file);
          if (/sentinel:ignore\s+AUTH-001/.test(source)) continue;
          findings.push(
            mkFinding(
              "AUTH-001",
              "critical",
              `${endpoint.method} ${endpoint.path} has no auth check`,
              "Mutation endpoint does not reference any auth/session API.",
              "Your API endpoint handles mutations (create, update, delete) without verifying who is making the request. Any anonymous user or bot can call this endpoint and modify your data.",
              "Add `supabase.auth.getUser()` and reject if the user is not authenticated.",
              [{ file: endpoint.file }],
              { cwe: "CWE-862", owasp: "A01:2021" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-011",
    domain: "auth-access-control",
    title: "GET endpoint uses service-role client without auth check",
    description:
      "GET handler imports SUPABASE_SERVICE_ROLE_KEY (or otherwise constructs a service-role Supabase client) and has no detectable auth check, exposing the entire underlying table to anyone who hits the URL.",
    impact:
      "Your GET endpoint queries Supabase using the service-role key, which bypasses Row Level Security. Because there is no auth check on the handler, any anonymous caller who hits this URL receives every row of the underlying table — portal users, audit logs, customer records, whatever the route reads.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-862", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        if (endpoint.method !== "GET") continue;
        if (!endpoint.usesServiceRole) continue;
        if (endpoint.hasAuthCheck) continue;
        // Respect an explicit suppression pragma so intentionally public
        // service-role reads (e.g., a public catalog API) don't generate noise.
        let source = "";
        try {
          source = await safeReadFile(endpoint.file);
        } catch {
          // If the file can't be read, fall back to flagging — better to
          // err toward more flags than silently drop a critical finding.
        }
        if (/sentinel:ignore\s+AUTH-011/.test(source)) continue;
        findings.push(
          mkFinding(
            "AUTH-011",
            "critical",
            `GET ${endpoint.path} reads with service role and no auth check`,
            "GET handler uses a service-role Supabase client (which bypasses RLS) and has no detectable auth gate, so the entire queried table is exposed to anonymous callers.",
            "Your GET endpoint queries Supabase using the service-role key, which bypasses Row Level Security. Because there is no auth check on the handler, any anonymous caller who hits this URL receives every row of the underlying table — portal users, audit logs, customer records, whatever the route reads.",
            "Add an auth gate at the top of the handler (e.g., `await requireStaffPermission(...)`, `await getServerUser()`, or `await supabase.auth.getUser()` followed by an explicit reject), OR move the read to the public anon-role Supabase client so RLS is enforced. If this endpoint is intentionally public, add `// sentinel:ignore AUTH-011` to the file to suppress this finding.",
            [{ file: endpoint.file }],
            { cwe: "CWE-862", owasp: "A01:2021" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "CONVENTION-001",
    domain: "auth-access-control",
    title: "Endpoint deviates from declared auth convention",
    description:
      "Project .sentinelrc.json declares a required auth helper for this path glob; this endpoint does not call it.",
    impact:
      "Established auth conventions exist for a reason — the project already has a vetted helper that handles session lookup, role checks, and rejection consistently. AI-generated routes commonly forget the convention and reach straight for a service-role client or a raw Supabase query, producing silent privilege bypasses that look identical to working endpoints from the outside. One real-world case: seven admin routes in a production app skipped the project's `requireStaffPermission` helper and used `createClient(URL, SERVICE_ROLE_KEY)` directly — every one was world-readable until the convention check caught it.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-862", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];

      // Conventions are declared in .sentinelrc.json. Rules don't currently
      // receive the loaded config (it's parsed in src/commands/scan.ts and
      // never attached to the model), so re-load from the project root.
      // loadConfig swallows the missing-file case and returns defaults, so
      // projects without a .sentinelrc.json simply have conventions = undefined.
      let conventions: ConventionRule[] | undefined;
      try {
        const cfg = await loadConfig(model.meta.path);
        conventions = cfg.conventions;
      } catch {
        // Malformed .sentinelrc.json → don't crash the rule pass; just skip
        // convention enforcement and let the parse error surface elsewhere.
        return findings;
      }
      if (!conventions || conventions.length === 0) return findings;

      for (const convention of conventions) {
        // Only auth conventions are meaningful right now. Defensive in case
        // future schema versions add domains we don't yet enforce.
        if ((convention.domain ?? "auth") !== "auth") continue;

        for (const endpoint of model.endpoints) {
          const rel = relPath(model.meta.path, endpoint.file);
          if (!pathMatches(rel, convention.match)) continue;

          let source = "";
          try {
            source = await safeReadFile(endpoint.file);
          } catch {
            // If the file is unreadable, skip — better than a phantom finding.
            continue;
          }

          // Honor an explicit suppression so an intentional deviation can
          // be marked as deliberate (e.g., a public webhook under an admin
          // glob that genuinely should not run the staff-permission check).
          if (/sentinel:ignore\s+CONVENTION-001/.test(source)) continue;

          if (callsHelper(source, convention.require)) continue;

          findings.push(
            mkFinding(
              "CONVENTION-001",
              "critical",
              `${endpoint.method} ${endpoint.path} skips required helper ${convention.require}()`,
              `Endpoint matches the convention glob "${convention.match}" but does not call ${convention.require}().`,
              "Established auth conventions exist for a reason — the project already has a vetted helper that handles session lookup, role checks, and rejection consistently. AI-generated routes commonly forget the convention and reach straight for a service-role client or a raw Supabase query, producing silent privilege bypasses that look identical to working endpoints from the outside.",
              `Call ${convention.require}() at the top of the handler before any data access, OR add \`// sentinel:ignore CONVENTION-001\` to the file if the deviation is intentional.`,
              [{ file: endpoint.file }],
              { cwe: "CWE-862", owasp: "A01:2021" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "PATTERN-001",
    domain: "auth-access-control",
    title: "Endpoint deviates from project's inferred auth pattern",
    description:
      "Pattern inference detected that most endpoints under a given path use a specific auth helper. This endpoint does not.",
    impact:
      "This pattern was inferred automatically from the rest of your codebase — verify before acting. When a clear majority of endpoints in a directory call the same auth helper and one route skips it, the most common cause is an AI-generated handler that lacked project context. The IslandFlow-style failure mode is silent privilege bypass: the endpoint compiles, deploys, and serves data, but skips the access check the rest of the project relies on.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-862", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];

      // inferredPatterns is optional on ProjectModel. Undefined or empty means
      // recon ran without inferring anything (small project, no convergence),
      // so we emit nothing rather than guess.
      const patterns = model.inferredPatterns ?? [];
      if (patterns.length === 0) return findings;

      // Defer to CONVENTION-001 when both rules would fire on the same file.
      // The user's explicit declaration wins over inferred priors. Resolving
      // CONVENTION-001 first avoids a duplicate finding on the same endpoint.
      // Also pull excludePathSegments here so the same set is used by inference
      // AND by deviation detection (login/signup/webhook endpoints excluded
      // from inference must also be excluded from PATTERN-001 flagging).
      const conventionFlaggedFiles = new Set<string>();
      let excludedSegments = DEFAULT_EXCLUDED_SEGMENTS;
      try {
        const cfg = await loadConfig(model.meta.path);
        if (cfg.patternInference?.excludePathSegments) {
          excludedSegments = cfg.patternInference.excludePathSegments;
        }
        const conventions = cfg.conventions ?? [];
        for (const c of conventions) {
          if ((c.domain ?? "auth") !== "auth") continue;
          for (const endpoint of model.endpoints) {
            const rel = relPath(model.meta.path, endpoint.file);
            if (!pathMatches(rel, c.match)) continue;
            let source = "";
            try { source = await safeReadFile(endpoint.file); } catch { continue; }
            if (/sentinel:ignore\s+CONVENTION-001/.test(source)) continue;
            if (callsHelper(source, c.require)) continue;
            // CONVENTION-001 would fire on this file → suppress PATTERN-001.
            conventionFlaggedFiles.add(endpoint.file);
          }
        }
      } catch {
        // Config unreadable → fall through; PATTERN-001 still operates on
        // inferred patterns alone with default exclusions. Worst case: a
        // duplicate finding the user can fix once.
      }

      for (const pattern of patterns) {
        if (pattern.domain !== "auth") continue;

        for (const endpoint of model.endpoints) {
          if (conventionFlaggedFiles.has(endpoint.file)) continue;
          // Auth-flow / webhook / cron endpoints legitimately deviate from the
          // session-helper pattern (login establishes the session; webhooks
          // use HMAC; crons use shared secrets). Skip them here for the same
          // reason inference excludes them from sample size.
          if (isExcludedPath(endpoint.file, excludedSegments)) continue;

          const rel = relPath(model.meta.path, endpoint.file);
          if (!pathMatches(rel, pattern.pathGlob)) continue;

          let source = "";
          try {
            source = await safeReadFile(endpoint.file);
          } catch {
            continue;
          }
          if (/sentinel:ignore\s+PATTERN-001/.test(source)) continue;
          if (callsHelper(source, pattern.dominantHelper)) continue;

          const pct = Math.round(pattern.prevalence * 100);
          findings.push(
            mkFinding(
              "PATTERN-001",
              "critical",
              `${endpoint.method} ${endpoint.path} skips inferred helper ${pattern.dominantHelper}()`,
              `Pattern inference detected that ${pct}% of endpoints under ${pattern.pathGlob} use ${pattern.dominantHelper} (n=${pattern.sampleSize}). This endpoint does not.`,
              "This pattern was inferred automatically from the rest of your codebase — verify before acting. When a clear majority of endpoints in a directory call the same auth helper and one route skips it, the most common cause is an AI-generated handler that lacked project context. The risk is silent privilege bypass: the endpoint compiles, deploys, and serves data, but skips the access check the rest of the project relies on.",
              `Call ${pattern.dominantHelper}() at the top of the handler before any data access. If this endpoint is intentionally public or uses a different (verified) auth path, add \`// sentinel:ignore PATTERN-001\` to the file.`,
              [{ file: endpoint.file }],
              { cwe: "CWE-862", owasp: "A01:2021" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-002",
    domain: "auth-access-control",
    title: "Supabase table referenced with no RLS migration found",
    description: "Table queried from code but not enabled in SQL migrations",
    impact: "Your app queries a Supabase table that has no Row Level Security policies. Any authenticated user can read or modify any row in this table, not just their own data.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-284" },
    async check(model) {
      const findings: Finding[] = [];
      const migrationsDir = ["supabase/migrations", "migrations"];
      let migrationContent = "";
      for (const dir of migrationsDir) {
        const files = await fg(["**/*.sql"], { cwd: `${model.meta.path}/${dir}`, absolute: true });
        for (const f of files) {
          try { migrationContent += await safeReadFile(f); } catch {}
        }
      }

      if (migrationContent) {
        const enableRls = migrationContent.match(/alter\s+table\s+(?:[\w.]+\.)?(\w+)\s+enable\s+row\s+level\s+security/gi) ?? [];
        const enabledTables = new Set(
          enableRls.map((m) => m.match(/alter\s+table\s+(?:[\w.]+\.)?(\w+)\s+enable/i)?.[1]).filter(Boolean) as string[],
        );

        // Collect names defined as VIEWs — views don't support RLS.
        const viewMatches = migrationContent.matchAll(/create\s+(?:or\s+replace\s+)?view\s+(?:[\w.]+\.)?(\w+)/gi);
        const viewNames = new Set<string>();
        for (const vm of viewMatches) {
          if (vm[1]) viewNames.add(vm[1]);
        }

        const tableRefs = new Set<string>();
        for (const endpoint of model.endpoints) {
          const source = await safeReadFile(endpoint.file);
          const matches = source.matchAll(/\.from\s*\(\s*["'](\w+)["']/g);
          for (const m of matches) tableRefs.add(m[1]);
        }

        // Collect the actual migration files to use as evidence instead of
        // pointing at the directory (which causes EISDIR when the fixer reads it).
        const migrationFiles = await fg(["**/*.sql"], {
          cwd: `${model.meta.path}/supabase/migrations`,
          absolute: true,
        }).catch(() => [] as string[]);

        for (const table of tableRefs) {
          // Views don't support RLS — skip them.
          if (viewNames.has(table)) continue;
          if (!enabledTables.has(table)) {
            // Use the first migration file as evidence, or skip if none exist
            const evidenceFile = migrationFiles[0];
            if (!evidenceFile) continue;
            findings.push(
              mkFinding(
                "AUTH-002",
                "high",
                `Table ${table} has no ENABLE ROW LEVEL SECURITY statement`,
                "Supabase table is queried from code but RLS is not enabled in migrations.",
                "Your app queries a Supabase table that has no Row Level Security policies. Any authenticated user can read or modify any row in this table, not just their own data.",
                `Run: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; and add appropriate policies.`,
                [{ file: evidenceFile }],
                { cwe: "CWE-284" },
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-003",
    domain: "auth-access-control",
    title: "JWT decoded client-side without server verification",
    description: "jwt-decode used in a client component",
    impact: "Your app decodes JWTs on the client side without verifying the signature on the server. An attacker can forge a token with any claims they want and your app will trust it.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-347" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file);
        if (/jwt-decode/.test(source) && /["']use client["']/.test(source)) {
          findings.push(
            mkFinding(
              "AUTH-003",
              "critical",
              "JWT decoded client-side",
              "Decoding a JWT on the client does not verify its signature.",
              "Your app decodes JWTs on the client side without verifying the signature on the server. An attacker can forge a token with any claims they want and your app will trust it.",
              "Verify tokens server-side. Use the decoded claims only for display, never for authorization.",
              [{ file }],
              { cwe: "CWE-347" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-004",
    domain: "auth-access-control",
    title: "Dynamic ID used without ownership check",
    description: "Route handler queries by params.id without filtering by user",
    impact: "Your API route fetches a record by ID from the URL without checking if the requesting user owns it. An attacker can enumerate IDs to access other users' data.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-639", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      for (const route of model.routes) {
        if (!route.paramNames.includes("id")) continue;
        const source = await safeReadFile(route.file);
        const queriesById = /\.eq\s*\(\s*["']id["']\s*,\s*params\.id/.test(source);
        const filtersByUser = /\.eq\s*\(\s*["'](user_id|owner_id|created_by)["']/.test(source);
        if (queriesById && !filtersByUser) {
          findings.push(
            mkFinding(
              "AUTH-004",
              "high",
              `${route.path} fetches by id without ownership check`,
              "Handler fetches a resource by ID without filtering on the authenticated user.",
              "Your API route fetches a record by ID from the URL without checking if the requesting user owns it. An attacker can enumerate IDs to access other users' data.",
              "Add `.eq('user_id', user.id)` or use RLS policies that enforce ownership.",
              [{ file: route.file }],
              { cwe: "CWE-639", owasp: "A01:2021" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-005",
    domain: "auth-access-control",
    title: "supabase.auth.admin used without server-only guard",
    description: "Admin API gives full access and must be behind a server-only boundary",
    impact: "Your app uses the Supabase admin API in code that could run client-side. The admin API bypasses all security policies and grants full database access to whoever calls it.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-269", owasp: "A01:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file);
        if (/supabase\.auth\.admin/.test(source)) {
          const serverOnly = /import\s+["']server-only["']/.test(source);
          if (!serverOnly) {
            findings.push(
              mkFinding(
                "AUTH-005",
                "critical",
                "supabase.auth.admin used without server-only guard",
                "Admin API usage must be confined to server-only modules.",
                "Your app uses the Supabase admin API in code that could run client-side. The admin API bypasses all security policies and grants full database access to whoever calls it.",
                'Add `import "server-only";` at the top of this file, or move the admin call into a file that does.',
                [{ file }],
                { cwe: "CWE-269", owasp: "A01:2021" },
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-006",
    domain: "auth-access-control",
    title: "Middleware matcher excludes API routes",
    description: "middleware.ts matcher skips /api/*",
    impact: "Your Next.js middleware skips API routes, meaning auth checks applied to pages do not protect your API endpoints. An attacker can call your APIs directly without being authenticated.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-284" },
    async check(model) {
      const findings: Finding[] = [];
      const candidates = ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"];
      for (const rel of candidates) {
        const file = `${model.meta.path}/${rel}`;
        try {
          const source = await safeReadFile(file);
          if (/matcher/.test(source) && /!api|api\/\*/.test(source)) {
            findings.push(
              mkFinding(
                "AUTH-006",
                "high",
                "Middleware matcher excludes API routes",
                "middleware.ts matcher skips /api/*, leaving API routes without auth.",
                "Your Next.js middleware skips API routes, meaning auth checks applied to pages do not protect your API endpoints. An attacker can call your APIs directly without being authenticated.",
                "Include `/api/:path*` in the matcher, or add per-route auth checks.",
                [{ file }],
                { cwe: "CWE-284" },
              ),
            );
          }
        } catch {}
      }
      return findings;
    },
  },

  {
    id: "AUTH-007",
    domain: "auth-access-control",
    title: "Session secret shorter than 32 characters",
    description: "A session/JWT signing secret is defined with fewer than 32 characters of entropy",
    impact: "Your session or JWT signing secret is too short. An attacker can brute-force a short secret and then forge valid session tokens for any user.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-326" },
    async check(model) {
      const findings: Finding[] = [];
      const reported = new Set<string>();

      // 1. Scan .env* files for short secrets.
      for (const relEnv of ENV_CANDIDATES) {
        const envPath = join(model.meta.path, relEnv);
        const contents = await readEnvFile(envPath);
        if (!contents) continue;
        const parsed = parseEnvFile(contents);
        for (const key of SESSION_SECRET_KEYS) {
          const value = parsed[key];
          if (value === undefined) continue;
          // Ignore variable references, stub values, and obvious empties.
          if (value === "" || value.startsWith("$") || /change[-_ ]?me|replace[-_ ]?me|changeme/i.test(value)) {
            findings.push(
              mkFinding(
                "AUTH-007",
                "high",
                `${key} is empty or stub value in ${relEnv}`,
                "A signing secret is unset or contains a stub value that was never replaced.",
                "Your session or JWT signing secret is too short. An attacker can brute-force a short secret and then forge valid session tokens for any user.",
                "Generate a high-entropy secret: `openssl rand -hex 32`. Store it in a secrets manager.",
                [{ file: envPath, snippet: `${key}=${value.slice(0, 12)}…` }],
                { cwe: "CWE-326" },
              ),
            );
            reported.add(key);
            continue;
          }
          if (value.length < 32) {
            findings.push(
              mkFinding(
                "AUTH-007",
                "high",
                `${key} is ${value.length} characters (< 32)`,
                "Short signing secrets are vulnerable to brute force and dictionary attacks.",
                "Your session or JWT signing secret is too short. An attacker can brute-force a short secret and then forge valid session tokens for any user.",
                "Generate a 32+ character random secret: `openssl rand -hex 32`.",
                [{ file: envPath, snippet: `${key}=<${value.length} chars>` }],
                { cwe: "CWE-326" },
              ),
            );
            reported.add(key);
          }
        }
      }

      // 2. Scan source for hardcoded short secrets passed to jwt.sign,
      // iron-session, cookie-session, etc.
      const files = await fg(["**/*.{ts,tsx,js,jsx,mjs,cjs}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**", "**/dist/**", "**/build/**"],
      });
      const literalSecret = /\b(jwt\.sign|jsonwebtoken\.sign|jose\.sign|sign)\s*\([^)]*?["']([^"']{1,31})["']/g;
      const cookieSecret = /(cookieName|password|secret)\s*:\s*["']([^"']{1,31})["']/g;
      for (const file of files) {
        const source = await safeReadFile(file);
        if (!/jwt|sign|session|cookie/i.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          for (const pattern of [literalSecret, cookieSecret]) {
            const r = new RegExp(pattern.source, pattern.flags);
            let m: RegExpExecArray | null;
            while ((m = r.exec(line)) !== null) {
              const secret = m[2];
              if (!secret || secret.length >= 32) continue;
              if (/change[-_]?me|example|test|todo/i.test(secret)) continue;
              findings.push(
                mkFinding(
                  "AUTH-007",
                  "high",
                  "Hardcoded signing secret shorter than 32 chars",
                  "Literal secret passed to a signing/session call.",
                  "Your session or JWT signing secret is too short. An attacker can brute-force a short secret and then forge valid session tokens for any user.",
                  "Move the secret to an environment variable, then generate a 32+ char random value.",
                  [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
                  { cwe: "CWE-326" },
                ),
              );
            }
          }
        });
      }

      return findings;
    },
  },

  {
    id: "AUTH-008",
    domain: "auth-access-control",
    title: "JWT algorithm set to none or weak",
    description: "alg: 'none' disables signature verification",
    impact: "Your JWT configuration allows the 'none' algorithm or a weak algorithm. An attacker can create unsigned tokens that your app accepts as valid.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-327" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file);
        if (/algorithm\s*:\s*["']none["']/.test(source)) {
          findings.push(
            mkFinding(
              "AUTH-008",
              "critical",
              "JWT algorithm set to 'none'",
              "alg: 'none' disables signature verification entirely.",
              "Your JWT configuration allows the 'none' algorithm or a weak algorithm. An attacker can create unsigned tokens that your app accepts as valid.",
              "Use RS256 or ES256 with a proper keypair. HS256 is acceptable with a 32+ char secret.",
              [{ file }],
              { cwe: "CWE-327" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-009",
    domain: "auth-access-control",
    title: "Role check based on user-controlled field",
    description: "Role comparison uses a field from request body",
    impact: "Your app checks user roles using a field from the request body. An attacker can set their own role to 'admin' in the request and your app will grant them elevated access.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-639" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**"],
      });
      for (const file of files) {
        const source = await safeReadFile(file);
        if (/body\.(role|isAdmin|admin)\s*===/.test(source)) {
          findings.push(
            mkFinding(
              "AUTH-009",
              "high",
              "Role check against request body",
              "Role determined from request body can be set by any client.",
              "Your app checks user roles using a field from the request body. An attacker can set their own role to 'admin' in the request and your app will grant them elevated access.",
              "Check role from the authenticated session or database, never from the request body.",
              [{ file }],
              { cwe: "CWE-639" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "AUTH-010",
    domain: "auth-access-control",
    title: "OAuth callback missing state validation",
    description: "OAuth callback handler does not verify state parameter",
    impact: "Your OAuth callback does not verify the state parameter. An attacker can trick a user into completing an OAuth flow that links the attacker's account, giving them access.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-352" },
    async check(model) {
      const findings: Finding[] = [];
      for (const route of model.routes) {
        if (!/callback/.test(route.path)) continue;
        const source = await safeReadFile(route.file);
        const hasState = /\bstate\b.*(searchParams|query)/.test(source);
        if (!hasState) {
          findings.push(
            mkFinding(
              "AUTH-010",
              "high",
              `${route.path} does not verify OAuth state`,
              "Missing state validation allows CSRF on OAuth flow.",
              "Your OAuth callback does not verify the state parameter. An attacker can trick a user into completing an OAuth flow that links the attacker's account, giving them access.",
              "Generate a random state before redirect, store in cookie, verify on callback.",
              [{ file: route.file }],
              { cwe: "CWE-352" },
            ),
          );
        }
      }
      return findings;
    },
  },
];
