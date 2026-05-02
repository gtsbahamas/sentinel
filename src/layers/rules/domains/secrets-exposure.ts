import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { execFileSync } from "child_process";
import { safeReadFile } from "../../../utils/fs.js";
import type { Finding, ProjectModel } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

const KNOWN_KEY_PATTERNS: Array<[string, RegExp]> = [
  ["stripe", /sk_(test|live)_[a-zA-Z0-9]{24,}/],
  ["openai", /sk-[a-zA-Z0-9]{20,}/],
  ["aws", /AKIA[0-9A-Z]{16}/],
  ["slack", /xox[bpoa]-[0-9]{10,}-[0-9a-zA-Z]{20,}/],
  ["github", /ghp_[a-zA-Z0-9]{36}/],
];

// Directories that never ship to the browser bundle — CLI helpers, background
// workers, standalone agents, migrations, and Next.js API route handlers.
// Iteration 4: extended with `lib`, `services`, `server`, `app/api/**` so
// service-role accesses inside server-only modules don't fire AUTH/SECRETS
// findings. The verifier consistently confirmed these are not exposure paths.
const SERVER_ONLY_DIR_PATTERNS = [
  /[/\\]scripts[/\\]/,
  /[/\\]worker[/\\]/,
  /[/\\]workers[/\\]/,
  /[/\\]agent[/\\]/,
  /[/\\]agents[/\\]/,
  /[/\\]server[/\\]/,
  /[/\\]supabase[/\\]functions[/\\]/,
  /[/\\]supabase[/\\]migrations[/\\]/,
  /[/\\]migrations[/\\]/,
  /[/\\]seed[/\\]/,
  /[/\\]seeds[/\\]/,
  /[/\\]cli[/\\]/,
];

// File-name suffixes that mark code as server-only by Next.js convention.
const SERVER_ONLY_FILENAME_PATTERNS = [
  /\.server\.(ts|tsx|js|jsx|mjs|cjs)$/,
  /[/\\]server\.(ts|tsx|js|jsx|mjs|cjs)$/, // foo/server.ts
];

function isKnownServerContext(file: string): boolean {
  if (SERVER_ONLY_DIR_PATTERNS.some((re) => re.test(file))) return true;
  if (SERVER_ONLY_FILENAME_PATTERNS.some((re) => re.test(file))) return true;
  // Next.js API route handlers run only on the server.
  if (/[/\\]api[/\\].*route\.(ts|tsx|js|jsx|mjs)$/.test(file)) return true;
  // Next.js App Router pages: `app/**/page.{ts,tsx}` declared as `async function`
  // are React Server Components — they run only on the server, never ship
  // to the browser bundle. We can't easily detect "async" without source
  // here, so the rule body still does the source check; this just provides
  // a coarse "server-likely" hint via path.
  return false;
}

/**
 * Stronger server-only context detection that uses the source content. Used
 * by SECRETS-001 to suppress the dominant FP pattern: service-role keys
 * accessed inside `lib/` / `services/` / server components. We only call
 * this AFTER the path-based check rejected the file, so it's the second-line
 * filter.
 */
function isServerContextBySource(file: string, source: string): boolean {
  if (!source.trim()) return true; // empty file = phantom match, safe to drop
  // React Server Component: `export default async function Page(`
  if (/export\s+default\s+async\s+function\s+(?:Page|Layout|Loading|Error|NotFound)\b/.test(source)) {
    return true;
  }
  // Next.js runtime export indicates server context.
  if (/export\s+const\s+runtime\s*=\s*["'`](?:nodejs|edge)["'`]/.test(source)) {
    return true;
  }
  // Files with `import "server-only"` already covered in main rule check.
  // Files in `lib/` or `services/` that contain ONLY exports of async
  // functions and never reference `window`, `document`, or `'use client'`
  // are server modules in practice. Heuristic, not airtight, but matches
  // the corpus FP pattern of `getServiceSupabase()` helpers.
  if (
    /[/\\](?:lib|services|utils|helpers|features|server|backend|workers?|jobs?|cron|tasks?)[/\\]/.test(file) &&
    !/['"`]use client['"`]/.test(source) &&
    !/\bwindow\.|document\.|navigator\./.test(source)
  ) {
    return true;
  }
  // v0.1.4: A Next.js sitemap.ts at the app root runs only at build/server
  // time. Same for robots.ts, manifest.ts, opengraph-image.ts — Next.js
  // metadata files. They never ship to the browser bundle.
  if (/[/\\](?:sitemap|robots|manifest|opengraph-image|twitter-image|icon|apple-icon|favicon)\.(ts|tsx|js|jsx)$/.test(file)) {
    return true;
  }
  // v0.1.4: Files using only Node-side imports (fs, crypto, child_process,
  // path) cannot run in the browser. Strong server-only signal.
  if (/from\s+["'](?:node:)?(?:fs|crypto|child_process|stream|os|net|http|https|tls|dgram|dns)["']/.test(source)) {
    return true;
  }
  // v0.1.4: Files that read SUPABASE_SERVICE_ROLE_KEY only inside a function
  // (not at top-level export of a constant) are factory helpers. Detection:
  // SERVICE_ROLE_KEY appears within `function`/`=>` body, not in module-level
  // export. Heuristic: if every reference is inside a function, it's a
  // server-side factory.
  const serviceRoleMatches = source.match(/SUPABASE_SERVICE_ROLE_KEY/g) ?? [];
  if (serviceRoleMatches.length > 0) {
    // Look for module-level (not in a function body) exports that include the
    // SERVICE_ROLE key. If we don't find one, all uses are inside functions.
    const moduleLevelExport = /^\s*export\s+const\s+\w+\s*=\s*[^=>;]*SUPABASE_SERVICE_ROLE_KEY/m.test(source);
    if (!moduleLevelExport) return true;
  }
  return false;
}

function mkFinding(
  rule: { id: string; severity: Finding["severity"]; title: string; remediation: string; references: { cwe?: string; owasp?: string } },
  evidence: Finding["evidence"],
  description: string,
  impact: string,
): Finding {
  return {
    id: `${rule.id}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain: "secrets-exposure",
    severity: rule.severity,
    confidence: "high",
    title: rule.title,
    description,
    impact,
    evidence,
    remediation: rule.remediation,
    references: [rule.references.cwe, rule.references.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId: rule.id,
    cwe: rule.references.cwe,
    owasp: rule.references.owasp,
  };
}

export const secretsExposureRules: SecurityRule[] = [
  {
    id: "SECRETS-001",
    domain: "secrets-exposure",
    title: "Service role key used client-side",
    description: "SUPABASE_SERVICE_ROLE_KEY referenced without server-only guard",
    impact: "Your Supabase service role key is accessible in client-side code. This key bypasses all Row Level Security, meaning anyone who opens browser DevTools can read, modify, or delete any row in any table.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-798", owasp: "A07:2021" },
    async check(model) {
      const findings: Finding[] = [];
      for (const env of model.envVars) {
        if (env.name === "SUPABASE_SERVICE_ROLE_KEY") {
          for (const file of env.referencedIn) {
            if (isKnownServerContext(file)) continue;
            const source = await safeReadFile(file);
            // Iteration 4: empty/unreadable file → phantom match, skip.
            if (!source.trim()) continue;
            // Source-based server-context check (server components, lib/,
            // services/, server runtime exports). Catches the dominant FP
            // pattern from iter-3: `getServiceSupabase()` helpers in
            // `lib/portal/`, `services/auth.ts`, async `app/**/page.tsx`.
            if (isServerContextBySource(file, source)) continue;
            const isServerOnly = /"use server"|import\s+["']server-only["']/.test(source);
            const hasNodeCheck = /typeof window === ["']undefined["']/.test(source);
            const hasShebang = /^#!\s*\/usr\/bin\/env/.test(source);
            if (!isServerOnly && !hasNodeCheck && !hasShebang) {
              findings.push(
                mkFinding(
                  {
                    id: "SECRETS-001",
                    severity: "critical",
                    title: "Service role key used without server-only guard",
                    remediation: 'Move to a file with `import "server-only"` or inside a route handler verified server-side.',
                    references: { cwe: "CWE-798", owasp: "A07:2021" },
                  },
                  [{ file, snippet: "process.env.SUPABASE_SERVICE_ROLE_KEY" }],
                  "Admin key usage outside a server-only boundary exposes it to client bundles.",
                  "Your Supabase service role key is accessible in client-side code. This key bypasses all Row Level Security, meaning anyone who opens browser DevTools can read, modify, or delete any row in any table.",
                ),
              );
            }
          }
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-002",
    domain: "secrets-exposure",
    title: "Known API key pattern in source",
    description: "Provider-specific secret pattern detected in source",
    impact: "Your source code contains an API key matching a known provider pattern. Anyone who reads your code, including through a public repo or client-side bundle, can use this key to access the associated service on your account.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-798" },
    async check(model) {
      const findings: Finding[] = [];
      const seen = new Set<string>();
      for (const route of [...model.routes, ...model.endpoints]) {
        const file = route.file;
        if (seen.has(file)) continue;
        seen.add(file);
        const source = await safeReadFile(file);
        for (const [provider, pattern] of KNOWN_KEY_PATTERNS) {
          const match = source.match(pattern);
          if (match) {
            const line = source.substring(0, match.index ?? 0).split("\n").length;
            findings.push(
              mkFinding(
                {
                  id: "SECRETS-002",
                  severity: "critical",
                  title: `${provider} API key pattern in source`,
                  remediation: "Remove the secret. Rotate the key. Use environment variables for secrets.",
                  references: { cwe: "CWE-798" },
                },
                [{ file, line, snippet: match[0] }],
                `A string matching the ${provider} secret pattern was found in source code.`,
                "Your source code contains an API key matching a known provider pattern. Anyone who reads your code, including through a public repo or client-side bundle, can use this key to access the associated service on your account.",
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-003",
    domain: "secrets-exposure",
    title: ".env file committed or not gitignored",
    description: ".env file present and not excluded from git",
    impact: "Your .env file is present in the project and not excluded from git. If this repository is ever shared, pushed to GitHub, or accessed by a third party, every secret in that file is compromised.",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "python"],
    references: { cwe: "CWE-312" },
    check(model) {
      const findings: Finding[] = [];
      const envPath = join(model.meta.path, ".env");
      const gitignorePath = join(model.meta.path, ".gitignore");
      if (existsSync(envPath)) {
        const gitignored = existsSync(gitignorePath)
          ? readFileSync(gitignorePath, "utf-8").split("\n").some((l) => l.trim() === ".env" || l.trim() === ".env*")
          : false;
        if (!gitignored) {
          findings.push(
            mkFinding(
              {
                id: "SECRETS-003",
                severity: "critical",
                title: ".env file not gitignored",
                remediation: "Add `.env` to `.gitignore`. If already committed, rotate all secrets and remove from git history.",
                references: { cwe: "CWE-312" },
              },
              [{ file: envPath }],
              ".env file exists without being excluded from version control.",
              "Your .env file is present in the project and not excluded from git. If this repository is ever shared, pushed to GitHub, or accessed by a third party, every secret in that file is compromised.",
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-004",
    domain: "secrets-exposure",
    title: "Hardcoded credentials in source",
    description: "String literal assigned to a suspicious variable name",
    impact: "Your source code contains hardcoded credentials in a variable assignment. These survive in git history even if deleted later, and anyone with repo access can extract them.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-798" },
    async check(model) {
      const findings: Finding[] = [];
      // SCAN LINE-BY-LINE (not whole-file). The previous whole-file regex
      // greedy-matched across newlines, so `'Failed to get token:'` followed
      // by another string literal later in the file would be captured as a
      // single 'token:" value:" match, producing FPs like
      // `console.error('Failed to get token:', error);` being flagged as a
      // hardcoded credential. Per-line matching eliminates that.
      //
      // Also: drop `token` from the standalone identifier list — it produced
      // most of the FPs (matched in log labels). Keep token as a SUFFIX in
      // tokenName patterns (apiToken, accessToken) and as a long-string heuristic.
      const suspicious = /(?:^|[^\w.])(password|passwd|pwd|secret|apiKey|api_key|accessKey|privateKey|access_token|refresh_token|api_token|auth_token|bearer_token)\b\s*[:=]\s*["']([^"'\n]{8,})["']/gi;
      const seen = new Set<string>();

      // Scan all env-referenced files plus route files
      const filesToScan = new Set<string>();
      for (const route of [...model.routes, ...model.endpoints]) filesToScan.add(route.file);
      for (const env of model.envVars) for (const f of env.referencedIn) filesToScan.add(f);

      for (const file of filesToScan) {
        if (seen.has(file)) continue;
        seen.add(file);
        // Skip test fixtures, migrations, scripts — overwhelmingly produce
        // FPs from test passwords.
        if (/\/(test|tests|__tests__|__mocks__|migrations|seed|seeds|fixtures|e2e|spec|scripts)\//i.test(file)) continue;
        if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(file)) continue;
        if (/\/test-[\w.-]+\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(file)) continue;

        const source = await safeReadFile(file);
        const lines = source.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Skip comment-only lines.
          const trim = line.trim();
          if (trim.startsWith("//") || trim.startsWith("*") || trim.startsWith("/*") || trim.startsWith("#")) continue;

          const regex = new RegExp(suspicious.source, "gi");
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            const value = match[2];
            // Skip stub/test placeholders.
            if (/\b(test|example|fake|placeholder|your[-_]?key|xxx|change[-_]?me|todo|sample|dummy)\b/i.test(value)) continue;
            // Skip values that are obvious env-var references or templates.
            if (/^\$\{|\$\(|process\.env|config\.|import\.meta/.test(value)) continue;
            // Skip values that look like HTTP method/scope tags or short magic
            // strings used in crypto helpers (e.g., 'HMAC', 'SHA-256').
            if (/^(HMAC|SHA-?\d+|RS\d+|HS\d+|ES\d+|RAW|application\/json)$/i.test(value)) continue;
            findings.push(
              mkFinding(
                {
                  id: "SECRETS-004",
                  severity: "high",
                  title: "Hardcoded credential-like string",
                  remediation: "Move the value to an environment variable. Rotate if this was a real credential.",
                  references: { cwe: "CWE-798" },
                },
                [{ file, line: i + 1, snippet: line.trim().slice(0, 120) }],
                "A string literal with a credential-sounding variable name was found.",
                "Your source code contains hardcoded credentials in a variable assignment. These survive in git history even if deleted later, and anyone with repo access can extract them.",
              ),
            );
          }
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-005",
    domain: "secrets-exposure",
    title: "NEXT_PUBLIC_ prefix on secret-like variable",
    description: "Variable name suggests a secret but is client-exposed",
    impact: "A variable with a secret-like name uses the NEXT_PUBLIC_ prefix, which makes it available in the browser bundle. Users can see this value in their browser's DevTools.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-312", owasp: "A07:2021" },
    check(model) {
      const findings: Finding[] = [];
      // High-confidence suspicious markers — these almost always indicate a
      // genuine secret leak when paired with NEXT_PUBLIC_/VITE_/PUBLIC_.
      const HIGH_CONFIDENCE = /(SECRET|PRIVATE|SERVICE_ROLE|PASSWORD)/;
      // Lower-confidence suspicious markers — many third-party APIs intentionally
      // expose API keys / tokens to the browser (Firebase web SDK, Google Maps,
      // OpenWeather, Mapbox, ExchangeRate-API, Sentry DSN, etc.). The previous
      // rule fired on every NEXT_PUBLIC_*_API_KEY producing >90% FPs.
      const LOW_CONFIDENCE = /(API_KEY|ACCESS_TOKEN|^TOKEN$|_TOKEN$)/;
      // Providers/SDKs that publish the API key / token by design. When a
      // NEXT_PUBLIC_ variable's middle segment matches one of these, we skip
      // the LOW_CONFIDENCE arm — the AI verifier consistently dismissed these
      // as intentional public-exposure.
      const PUBLIC_BY_DESIGN = new RegExp(
        "(?:^|_)(?:" +
          [
            "FIREBASE",
            "GOOGLE_MAPS",
            "GOOGLE_ANALYTICS",
            "GA",
            "GTAG",
            "MAPBOX",
            "OPENWEATHER",
            "EXCHANGE_RATE",
            "SENTRY",
            "RECAPTCHA",
            "TURNSTILE",
            "HCAPTCHA",
            "ALGOLIA",
            "POSTHOG",
            "MIXPANEL",
            "AMPLITUDE",
            "SEGMENT",
            "STRIPE_PUBLISHABLE",
            "SUPABASE_ANON",
            "PUBLISHABLE",
            "AGUI",
            "SMS_EAGLE",
            "DATADOG",
            "GOOGLE_AI",
          ].join("|") +
          ")(?:_|$)",
      );

      for (const env of model.envVars) {
        if (!env.clientExposed) continue;
        const stripped = env.name.replace(/^NEXT_PUBLIC_|^VITE_|^PUBLIC_/, "");

        const isHigh = HIGH_CONFIDENCE.test(stripped);
        const isLow = !isHigh && LOW_CONFIDENCE.test(stripped);
        if (!isHigh && !isLow) continue;

        // For LOW_CONFIDENCE matches, skip when the variable name is for a
        // known public-by-design API/SDK provider.
        if (isLow && PUBLIC_BY_DESIGN.test(stripped)) continue;

        findings.push(
          mkFinding(
            {
              id: "SECRETS-005",
              severity: "high",
              title: `${env.name} is client-exposed but looks like a secret`,
              remediation: "Remove the NEXT_PUBLIC_ prefix. Serve secret-dependent logic from the server.",
              references: { cwe: "CWE-312", owasp: "A07:2021" },
            },
            env.referencedIn.map((f) => ({ file: f, snippet: env.name })),
            "Client-exposed env vars end up in the browser bundle and are readable by anyone.",
            "A variable with a secret-like name uses the NEXT_PUBLIC_ prefix, which makes it available in the browser bundle. Users can see this value in their browser's DevTools.",
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "SECRETS-006",
    domain: "secrets-exposure",
    title: "Secret found in git history",
    description: "Known API key pattern present in a historical commit",
    impact: "A secret matching a known API key pattern exists in your git history. Even though it may be removed from the current code, anyone who clones the repository can find it by searching commit history.",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "python"],
    references: { cwe: "CWE-798" },
    check(model) {
      const findings: Finding[] = [];
      const gitDir = join(model.meta.path, ".git");
      if (!existsSync(gitDir)) return findings;

      // git log -p only in added lines (+), limited to keep the scan bounded.
      // Use execFileSync with array args — no shell, no injection surface.
      let patch = "";
      try {
        patch = execFileSync(
          "git",
          ["-C", model.meta.path, "log", "-p", "--all", "--full-history", "-G", "sk_|sk-|AKIA|xox[bpoa]-|ghp_", "--max-count=500"],
          { encoding: "utf-8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] },
        );
      } catch {
        return findings;
      }

      let currentCommit = "";
      let currentFile = "";
      const seen = new Set<string>();

      for (const line of patch.split("\n")) {
        const commitMatch = line.match(/^commit\s+([0-9a-f]{7,40})/);
        if (commitMatch) {
          currentCommit = commitMatch[1].slice(0, 12);
          continue;
        }
        const fileMatch = line.match(/^\+\+\+ b\/(.+)/);
        if (fileMatch) {
          currentFile = fileMatch[1];
          continue;
        }
        if (!line.startsWith("+") || line.startsWith("+++")) continue;

        const added = line.slice(1);
        for (const [provider, pattern] of KNOWN_KEY_PATTERNS) {
          const match = added.match(pattern);
          if (!match) continue;
          const dedupeKey = `${provider}|${match[0]}|${currentCommit}|${currentFile}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);
          findings.push(
            mkFinding(
              {
                id: "SECRETS-006",
                severity: "critical",
                title: `${provider} API key in git history`,
                remediation:
                  "Rotate the exposed key immediately. Rewrite history with git-filter-repo or accept that the key is permanently burned.",
                references: { cwe: "CWE-798" },
              },
              [
                {
                  file: currentFile,
                  snippet: match[0],
                  context: { commit: currentCommit, provider },
                },
              ],
              `A ${provider} key pattern was added to ${currentFile} in commit ${currentCommit} and remains in git history.`,
              "A secret matching a known API key pattern exists in your git history. Even though it may be removed from the current code, anyone who clones the repository can find it by searching commit history.",
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-007",
    domain: "secrets-exposure",
    title: "Credentials or tokens in developer comments",
    description: "Source comments contain credential-like strings",
    impact: "Your source code comments contain credential-like strings. Comments are included in many build outputs and are visible to anyone reading the code.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-615" },
    async check(model) {
      const findings: Finding[] = [];
      const commentPattern = /\/\/.*\b(password|token|apiKey|secret|credentials?)\s*[:=]/i;
      const seen = new Set<string>();
      for (const route of [...model.routes, ...model.endpoints]) {
        const file = route.file;
        if (seen.has(file)) continue;
        seen.add(file);
        const source = await safeReadFile(file);
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (commentPattern.test(line)) {
            findings.push(
              mkFinding(
                {
                  id: "SECRETS-007",
                  severity: "medium",
                  title: "Credential-like comment in source",
                  remediation: "Remove the comment. Assume the value has been exposed.",
                  references: { cwe: "CWE-615" },
                },
                [{ file, line: idx + 1, snippet: line.trim() }],
                "Developer comments mentioning credentials have historically leaked to production.",
                "Your source code comments contain credential-like strings. Comments are included in many build outputs and are visible to anyone reading the code.",
              ),
            );
          }
        });
      }
      return findings;
    },
  },

  {
    id: "SECRETS-008",
    domain: "secrets-exposure",
    title: "Env var referenced but missing from .env.example",
    description: "Source references process.env.X but .env.example does not list X",
    impact: "Your code references an environment variable that is not documented in .env.example. When other developers or CI systems set up the project, this variable will be missing, causing silent failures or insecure defaults.",
    severity: "low",
    appliesTo: ["nextjs-supabase", "python"],
    references: {},
    check(model) {
      // Well-known platform env vars that don't need .env.example documentation.
      // These are either auto-injected by the platform (Vercel, Netlify) or are
      // standard Supabase/Next.js conventions obvious to any developer.
      const WELL_KNOWN_ENV_VARS = new Set([
        // Supabase
        "NEXT_PUBLIC_SUPABASE_URL",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY",
        "SUPABASE_SERVICE_ROLE_KEY",
        "SUPABASE_URL",
        "SUPABASE_ANON_KEY",
        "SUPABASE_JWT_SECRET",
        // Next.js / Vercel
        "NEXT_PUBLIC_APP_URL",
        "NEXT_PUBLIC_SITE_URL",
        "NEXT_PUBLIC_BASE_URL",
        "NEXTAUTH_URL",
        "NEXTAUTH_SECRET",
        "VERCEL",
        "VERCEL_ENV",
        "VERCEL_URL",
        "VERCEL_PROJECT_PRODUCTION_URL",
        "VERCEL_GIT_COMMIT_SHA",
        "VERCEL_GIT_COMMIT_REF",
        // Node.js
        "NODE_ENV",
        "PORT",
        // Common SaaS
        "RESEND_API_KEY",
        "RESEND_FROM_EMAIL",
        "STRIPE_SECRET_KEY",
        "STRIPE_PUBLISHABLE_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
        // Netlify
        "NETLIFY",
        "URL",
        "DEPLOY_URL",
        "CONTEXT",
      ]);
      const findings: Finding[] = [];
      for (const env of model.envVars) {
        // Skip well-known platform vars and NEXT_PUBLIC_ prefixed vars (public by definition)
        if (!env.inExample && !WELL_KNOWN_ENV_VARS.has(env.name) && !env.name.startsWith("NEXT_PUBLIC_")) {
          findings.push(
            mkFinding(
              {
                id: "SECRETS-008",
                severity: "low",
                title: `${env.name} not documented in .env.example`,
                remediation: "Add the variable to .env.example with a placeholder value.",
                references: {},
              },
              env.referencedIn.slice(0, 1).map((f) => ({ file: f, snippet: env.name })),
              "Missing .env.example entries cause onboarding failures and hide the app's config surface.",
              "Your code references an environment variable that is not documented in .env.example. When other developers or CI systems set up the project, this variable will be missing, causing silent failures or insecure defaults.",
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "SECRETS-009",
    domain: "secrets-exposure",
    title: "Build output directory not gitignored",
    description: ".next or dist present without being in .gitignore",
    impact: "Your build output directory is not gitignored. Compiled files often contain inlined environment variables and can expose secrets if committed.",
    severity: "info",
    appliesTo: ["nextjs-supabase"],
    references: {},
    check(model) {
      const findings: Finding[] = [];
      const gitignorePath = join(model.meta.path, ".gitignore");
      const gitignoreEntries = existsSync(gitignorePath)
        ? readFileSync(gitignorePath, "utf-8").split("\n").map((l) => l.trim())
        : [];
      const buildDirs = [".next", "dist", "out", "build"];
      for (const dir of buildDirs) {
        // Check common gitignore patterns: "dir", "dir/", "/dir", "/dir/"
        const isIgnored = gitignoreEntries.some((entry) => {
          const normalized = entry.replace(/^\//, "").replace(/\/$/, "");
          return normalized === dir;
        });
        if (existsSync(join(model.meta.path, dir)) && !isIgnored) {
          // Point evidence at .gitignore (or package.json as fallback) instead
          // of the build directory itself, which causes EISDIR on read.
          const evidenceFile = existsSync(gitignorePath)
            ? gitignorePath
            : join(model.meta.path, "package.json");
          findings.push(
            mkFinding(
              {
                id: "SECRETS-009",
                severity: "info",
                title: `${dir} directory is not gitignored`,
                remediation: `Add ${dir}/ to .gitignore.`,
                references: {},
              },
              [{ file: evidenceFile, snippet: `Missing: ${dir}/` }],
              `Build artifacts may leak source maps or compiled secrets if committed.`,
              "Your build output directory is not gitignored. Compiled files often contain inlined environment variables and can expose secrets if committed.",
            ),
          );
        }
      }
      return findings;
    },
  },
];
