import { safeReadFile } from "../../../utils/fs.js";
import fg from "fast-glob";
import type { Finding } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  severity: Finding["severity"],
  title: string,
  description: string,
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
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-862", owasp: "A01:2021" },
    check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        if (["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method) && !endpoint.hasAuthCheck) {
          findings.push(
            mkFinding(
              "AUTH-001",
              "critical",
              `${endpoint.method} ${endpoint.path} has no auth check`,
              "Mutation endpoint does not reference any auth/session API.",
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
    id: "AUTH-002",
    domain: "auth-access-control",
    title: "Supabase table referenced with no RLS migration found",
    description: "Table queried from code but not enabled in SQL migrations",
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
        const enableRls = migrationContent.match(/alter\s+table\s+(\w+)\s+enable\s+row\s+level\s+security/gi) ?? [];
        const enabledTables = new Set(
          enableRls.map((m) => m.match(/alter\s+table\s+(\w+)/i)?.[1]).filter(Boolean) as string[],
        );

        const tableRefs = new Set<string>();
        for (const endpoint of model.endpoints) {
          const source = await safeReadFile(endpoint.file);
          const matches = source.matchAll(/\.from\s*\(\s*["'](\w+)["']/g);
          for (const m of matches) tableRefs.add(m[1]);
        }

        for (const table of tableRefs) {
          if (!enabledTables.has(table)) {
            findings.push(
              mkFinding(
                "AUTH-002",
                "high",
                `Table ${table} has no ENABLE ROW LEVEL SECURITY statement`,
                "Supabase table is queried from code but RLS is not enabled in migrations.",
                `Run: ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY; and add appropriate policies.`,
                [{ file: `${model.meta.path}/supabase/migrations/` }],
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
    description: "Placeholder - requires reading .env which is denied",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-326" },
    check() {
      return [];
    },
  },

  {
    id: "AUTH-008",
    domain: "auth-access-control",
    title: "JWT algorithm set to none or weak",
    description: "alg: 'none' disables signature verification",
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
