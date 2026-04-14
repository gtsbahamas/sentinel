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
const SERVER_ONLY_DIR_PATTERNS = [
  /[/\\]scripts[/\\]/,
  /[/\\]worker[/\\]/,
  /[/\\]agent[/\\]/,
  /[/\\]supabase[/\\]functions[/\\]/,
  /[/\\]supabase[/\\]migrations[/\\]/,
];

function isKnownServerContext(file: string): boolean {
  if (SERVER_ONLY_DIR_PATTERNS.some((re) => re.test(file))) return true;
  // Next.js API route handlers run only on the server.
  if (/[/\\]api[/\\].*route\.(ts|tsx|js|jsx|mjs)$/.test(file)) return true;
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
    appliesTo: ["nextjs-supabase"],
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
      const suspicious = /\b(password|passwd|pwd|secret|apiKey|api_key|token|accessKey|privateKey)\b\s*[:=]\s*["']([^"']{8,})["']/gi;
      const seen = new Set<string>();

      // Scan all env-referenced files plus route files
      const filesToScan = new Set<string>();
      for (const route of [...model.routes, ...model.endpoints]) filesToScan.add(route.file);
      for (const env of model.envVars) for (const f of env.referencedIn) filesToScan.add(f);

      for (const file of filesToScan) {
        if (seen.has(file)) continue;
        seen.add(file);
        const source = await safeReadFile(file);
        const regex = new RegExp(suspicious.source, "gi");
        let match;
        while ((match = regex.exec(source)) !== null) {
          const line = source.substring(0, match.index).split("\n").length;
          if (/\b(test|example|fake|placeholder)\b/i.test(match[2])) continue;
          findings.push(
            mkFinding(
              {
                id: "SECRETS-004",
                severity: "high",
                title: "Hardcoded credential-like string",
                remediation: "Move the value to an environment variable. Rotate if this was a real credential.",
                references: { cwe: "CWE-798" },
              },
              [{ file, line, snippet: match[0] }],
              "A string literal with a credential-sounding variable name was found.",
              "Your source code contains hardcoded credentials in a variable assignment. These survive in git history even if deleted later, and anyone with repo access can extract them.",
            ),
          );
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
      const suspicious = /(SECRET|PRIVATE|TOKEN|API_KEY|SERVICE_ROLE|PASSWORD)/;
      for (const env of model.envVars) {
        if (env.clientExposed && suspicious.test(env.name.replace(/^NEXT_PUBLIC_|^VITE_|^PUBLIC_/, ""))) {
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
    appliesTo: ["nextjs-supabase"],
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
    appliesTo: ["nextjs-supabase"],
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
