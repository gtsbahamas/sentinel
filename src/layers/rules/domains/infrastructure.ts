import { existsSync, readFileSync } from "fs";
import { join } from "path";
import fg from "fast-glob";
import { safeReadFile, readEnvFile, parseEnvFile } from "../../../utils/fs.js";
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
    domain: "infrastructure",
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

/** Heuristic: returns true if the trimmed line looks like a comment. */
function isCommentLine(line: string): boolean {
  const t = line.trim();
  return (
    t.startsWith("//") ||
    t.startsWith("/*") ||
    t.startsWith("*") || // inner line of block comment
    t.startsWith("#") // shell-style comment in config files
  );
}

function infraFiles(model: ProjectModel): string[] {
  const out: string[] = [];
  if (model.infra.nextConfig) out.push(model.infra.nextConfig.file);
  if (model.infra.middleware) out.push(model.infra.middleware.file);
  if (model.infra.vercelConfig) out.push(model.infra.vercelConfig.file);
  if (out.length === 0) out.push(join(model.meta.path, "next.config.mjs"));
  return out;
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
    ],
  });
  return Promise.all(files.map(async (file) => ({ file, source: await safeReadFile(file) })));
}

export const infrastructureRules: SecurityRule[] = [
  {
    id: "INFRA-001",
    domain: "infrastructure",
    title: "Content-Security-Policy header missing",
    description: "No CSP header configured in next.config, middleware, or vercel.json",
    impact:
      "Your app has no Content Security Policy header. An attacker who finds any XSS vulnerability can load scripts from any domain, making exploitation trivial and persistent.",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-693" },
    check(model) {
      const findings: Finding[] = [];
      if (!model.infra.securityHeaders["content-security-policy"]) {
        findings.push(
          mkFinding(
            "INFRA-001",
            "high",
            "No Content-Security-Policy header",
            "Without a CSP, a single XSS hole can load arbitrary scripts, iframes, and exfiltrate data.",
            "Your app has no Content Security Policy header. An attacker who finds any XSS vulnerability can load scripts from any domain, making exploitation trivial and persistent.",
            "Add a CSP in next.config headers() (or middleware) restricting script-src, connect-src, and frame-ancestors.",
            infraFiles(model).map((file) => ({ file })),
            { cwe: "CWE-693" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "INFRA-002",
    domain: "infrastructure",
    title: "Strict-Transport-Security header missing",
    description: "HSTS not configured",
    impact:
      "Your app does not set the Strict-Transport-Security header. An attacker on a public wifi network can intercept the first HTTP request before it redirects to HTTPS, stealing cookies or injecting content.",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-319" },
    check(model) {
      const findings: Finding[] = [];
      // Any web deployment is likely served over HTTPS. Only skip if
      // deployTarget is explicitly known to be non-TLS (none currently).
      const nonTlsDeploys = new Set<string>();
      const isTlsDeploy =
        model.meta.deployTarget === null || !nonTlsDeploys.has(model.meta.deployTarget);
      const missing = !model.infra.securityHeaders["strict-transport-security"];
      if (isTlsDeploy && missing) {
        findings.push(
          mkFinding(
            "INFRA-002",
            "high",
            "No Strict-Transport-Security header",
            "HSTS prevents downgrade attacks to plain HTTP and cookie leakage on the first request of a session.",
            "Your app does not set the Strict-Transport-Security header. An attacker on a public wifi network can intercept the first HTTP request before it redirects to HTTPS, stealing cookies or injecting content.",
            "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` to the response headers.",
            infraFiles(model).map((file) => ({ file })),
            { cwe: "CWE-319" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "INFRA-003",
    domain: "infrastructure",
    title: "X-Frame-Options header missing",
    description: "No clickjacking protection configured",
    impact:
      "Your app has no X-Frame-Options header. An attacker can embed your app in an invisible iframe on their site and trick users into clicking buttons they cannot see.",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-1021" },
    check(model) {
      const findings: Finding[] = [];
      const hasXfo = model.infra.securityHeaders["x-frame-options"];
      const csp = model.infra.securityHeaders["content-security-policy"]?.[0]?.value ?? "";
      const hasFrameAncestors = /frame-ancestors/.test(csp);
      if (!hasXfo && !hasFrameAncestors) {
        findings.push(
          mkFinding(
            "INFRA-003",
            "medium",
            "No X-Frame-Options or frame-ancestors directive",
            "Any origin can embed this site in an iframe, enabling clickjacking.",
            "Your app has no X-Frame-Options header. An attacker can embed your app in an invisible iframe on their site and trick users into clicking buttons they cannot see.",
            "Set `X-Frame-Options: DENY` or add `frame-ancestors 'none'` to your CSP.",
            infraFiles(model).map((file) => ({ file })),
            { cwe: "CWE-1021" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "INFRA-004",
    domain: "infrastructure",
    title: "Wildcard CORS in config",
    description: "next.config or middleware sets Access-Control-Allow-Origin: *",
    impact:
      "Your app allows CORS requests from any origin. Any website can make JavaScript requests to your API, potentially reading responses if the user is authenticated.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-942" },
    check(model) {
      const findings: Finding[] = [];
      const origins = model.infra.securityHeaders["access-control-allow-origin"] ?? [];
      for (const origin of origins) {
        if (origin.value.trim() !== "*") continue;
        findings.push(
          mkFinding(
            "INFRA-004",
            "high",
            "Wildcard CORS origin in infrastructure config",
            "Access-Control-Allow-Origin: * applies to every request that hits the matching path pattern.",
            "Your app allows CORS requests from any origin. Any website can make JavaScript requests to your API, potentially reading responses if the user is authenticated.",
            "Replace `*` with an explicit list of trusted origins, or reflect the request origin only if it matches an allowlist.",
            [{ file: origin.file, snippet: "Access-Control-Allow-Origin: *" }],
            { cwe: "CWE-942" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "INFRA-005",
    domain: "infrastructure",
    title: "Cookies set without Secure flag",
    description: "Source sets a Set-Cookie response without Secure",
    impact:
      "Your app sets cookies without the Secure flag. On any non-HTTPS connection, like a coffee shop wifi captive portal, these cookies are sent in plaintext and can be intercepted.",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-614" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const setCookieRe = /cookies\s*\(\s*\)\s*\.set|response\.cookies\.set|Set-Cookie|res\.cookie\s*\(/;
      for (const { file, source } of files) {
        if (!setCookieRe.test(source)) continue;
        const lines = source.split("\n");
        // Check whether *any* cookie-setting line is paired with secure: true
        // within the same logical block (nearby lines). A file-wide check is
        // too coarse when a file sets multiple cookies.
        const cookieLines: number[] = [];
        lines.forEach((line, idx) => {
          if (setCookieRe.test(line) && !isCommentLine(line)) cookieLines.push(idx);
        });
        if (cookieLines.length === 0) continue;
        for (const cidx of cookieLines) {
          // Look in a +-5 line window for secure: true
          const windowStart = Math.max(0, cidx - 5);
          const windowEnd = Math.min(lines.length, cidx + 6);
          const window = lines.slice(windowStart, windowEnd).join("\n");
          if (/secure\s*:\s*true/.test(window)) continue;
          findings.push(
            mkFinding(
              "INFRA-005",
              "high",
              "Cookie set without Secure flag",
              "Cookies without Secure can be sent over plain HTTP and captured by a network attacker.",
              "Your app sets cookies without the Secure flag. On any non-HTTPS connection, like a coffee shop wifi captive portal, these cookies are sent in plaintext and can be intercepted.",
              "Set `secure: true` and `httpOnly: true` and `sameSite: 'lax'` (or 'strict') on all session cookies.",
              [{ file, line: cidx + 1, snippet: lines[cidx].trim().slice(0, 120) }],
              { cwe: "CWE-614" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "INFRA-006",
    domain: "infrastructure",
    title: "HTTP origin allowed in fetch/axios/CORS config",
    description: "Plain http:// URL in source or config",
    impact:
      "Your app communicates with external services over plain HTTP. Any network between your server and the service can read or modify the data in transit.",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-319" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const re = /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"']+["']/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!re.test(line)) return;
          if (isCommentLine(line)) return;
          // SVG xmlns attributes use http:// as a namespace identifier, not a network request
          if (/xmlns\s*=\s*["']http:\/\//.test(line)) return;
          findings.push(
            mkFinding(
              "INFRA-006",
              "medium",
              "Plain HTTP URL in source",
              "HTTP connections are subject to MITM injection and can leak credentials.",
              "Your app communicates with external services over plain HTTP. Any network between your server and the service can read or modify the data in transit.",
              "Use HTTPS for every non-localhost endpoint.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-319" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "INFRA-007",
    domain: "infrastructure",
    title: "Next.js images.remotePatterns allows wildcard host",
    description: "next.config has a wildcard hostname in remotePatterns",
    impact:
      "Your Next.js image configuration allows loading images from any host. An attacker can abuse your image proxy to fetch internal resources or use your server's bandwidth.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-601" },
    check(model) {
      const findings: Finding[] = [];
      const cfg = model.infra.nextConfig;
      if (!cfg) {
        return findings;
      }
      // Look for { hostname: "**" } or { hostname: "*" } or domains: ["*"].
      const wildcardRe = /hostname\s*:\s*["'](\*\*?|\*\.)/;
      const domainsWildcardRe = /domains\s*:\s*\[[^\]]*["']\*/;
      if (wildcardRe.test(cfg.source) || domainsWildcardRe.test(cfg.source)) {
        findings.push(
          mkFinding(
            "INFRA-007",
            "medium",
            "Next.js image optimizer trusts any host",
            "An attacker can request `/_next/image?url=https://evil.com/x.png` to proxy arbitrary URLs through your origin.",
            "Your Next.js image configuration allows loading images from any host. An attacker can abuse your image proxy to fetch internal resources or use your server's bandwidth.",
            "Set `images.remotePatterns` to an explicit list of hostnames (e.g. your Supabase project URL).",
            [{ file: cfg.file }],
            { cwe: "CWE-601" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "INFRA-008",
    domain: "infrastructure",
    title: "Production .env file committed",
    description: ".env or .env.production exists in the working tree",
    impact:
      "Your .env file is present in the project directory and not excluded from version control. If this code is shared or pushed to a remote, every secret in the file is exposed.",
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-312" },
    check(model) {
      const findings: Finding[] = [];
      const offenders = [".env", ".env.production", ".env.local"];
      const gitignorePath = join(model.meta.path, ".gitignore");
      const gitignoreLines = existsSync(gitignorePath)
        ? readFileSync(gitignorePath, "utf-8")
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l.length > 0 && !l.startsWith("#"))
        : [];
      const gitignored = new Set(gitignoreLines);
      for (const f of offenders) {
        const full = join(model.meta.path, f);
        if (!existsSync(full)) continue;
        // Check exact match, directory match, and common glob patterns.
        const ignored =
          gitignored.has(f) ||
          gitignored.has(`${f}/`) ||
          gitignored.has(".env*") ||
          gitignored.has(".env*.local") ||
          // Handle wildcard suffix patterns like *.local covering .env.local
          gitignoreLines.some((pattern) => {
            // Skip negation patterns
            if (pattern.startsWith("!")) return false;
            // Simple glob: *.ext
            if (pattern.startsWith("*.")) {
              return f.endsWith(pattern.slice(1));
            }
            return false;
          });
        if (ignored) continue;
        findings.push(
          mkFinding(
            "INFRA-008",
            "critical",
            `${f} is present and not gitignored`,
            "Committing env files ships secrets into the repo permanently.",
            "Your .env file is present in the project directory and not excluded from version control. If this code is shared or pushed to a remote, every secret in the file is exposed.",
            `Add \`${f}\` to .gitignore and rotate every secret it ever contained.`,
            [{ file: full }],
            { cwe: "CWE-312" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "INFRA-009",
    domain: "infrastructure",
    title: "Referrer-Policy header missing or permissive",
    description: "No Referrer-Policy, or set to unsafe-url",
    impact:
      "Your app has no Referrer-Policy or uses an unsafe one. When users navigate from your app to external sites, the full URL including query parameters is sent as the referrer, potentially leaking tokens or session data.",
    severity: "low",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-200" },
    check(model) {
      const findings: Finding[] = [];
      const headers = model.infra.securityHeaders["referrer-policy"];
      if (!headers) {
        findings.push(
          mkFinding(
            "INFRA-009",
            "low",
            "No Referrer-Policy header",
            "Without a policy, full URLs (including query strings with tokens) leak in the Referer header to third-party links.",
            "Your app has no Referrer-Policy or uses an unsafe one. When users navigate from your app to external sites, the full URL including query parameters is sent as the referrer, potentially leaking tokens or session data.",
            "Set `Referrer-Policy: strict-origin-when-cross-origin` at minimum.",
            infraFiles(model).map((file) => ({ file })),
            { cwe: "CWE-200" },
          ),
        );
        return findings;
      }
      for (const h of headers) {
        if (/unsafe-url|no-referrer-when-downgrade/i.test(h.value)) {
          findings.push(
            mkFinding(
              "INFRA-009",
              "low",
              `Permissive Referrer-Policy: ${h.value}`,
              "Unsafe referrer policies leak full URLs across origins.",
              "Your app has no Referrer-Policy or uses an unsafe one. When users navigate from your app to external sites, the full URL including query parameters is sent as the referrer, potentially leaking tokens or session data.",
              "Use `strict-origin-when-cross-origin` or `no-referrer`.",
              [{ file: h.file, snippet: `Referrer-Policy: ${h.value}` }],
              { cwe: "CWE-200" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "INFRA-010",
    domain: "infrastructure",
    title: "Supabase config has disabled email confirmations",
    description: "supabase/config.toml sets enable_confirmations = false for the email provider",
    impact:
      "Your Supabase config has email confirmations disabled. Anyone can sign up with a fake email address and immediately access authenticated features without proving they own the email.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-287" },
    async check(model) {
      const findings: Finding[] = [];
      const cfg = model.infra.supabaseConfig;
      if (!cfg) {
        return findings;
      }
      // Look inside [auth.email] section for enable_confirmations = false.
      const emailSection = cfg.source.match(/\[auth\.email\]([\s\S]*?)(?=\n\[|$)/);
      const disabled = emailSection && /enable_confirmations\s*=\s*false/.test(emailSection[1]);
      if (disabled) {
        findings.push(
          mkFinding(
            "INFRA-010",
            "medium",
            "Supabase email confirmations disabled",
            "With confirmations off, anyone can sign up with an email they don't own and receive password reset tokens for it.",
            "Your Supabase config has email confirmations disabled. Anyone can sign up with a fake email address and immediately access authenticated features without proving they own the email.",
            "Set `enable_confirmations = true` under `[auth.email]` in supabase/config.toml.",
            [{ file: cfg.file }],
            { cwe: "CWE-287" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "INFRA-011",
    domain: "infrastructure",
    title: "Dynamic access to NEXT_PUBLIC_* env var (will be undefined in client bundle)",
    description:
      "process.env is accessed with a computed key in a file that references NEXT_PUBLIC_ vars. Next.js only inlines NEXT_PUBLIC_* values at build time when they appear as static literal property accesses (process.env.NEXT_PUBLIC_FOO). Computed access returns undefined in the client bundle.",
    impact:
      "At runtime in the browser, the env var resolves to undefined and any code that depends on it crashes. This typically shows up as a white screen on the first client render — the whole page breaks, not just the feature using the var. It builds cleanly and passes typecheck, so it ships silently to production.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-1188" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      for (const { file, source } of files) {
        // Only flag files that actually deal with NEXT_PUBLIC_* vars.
        // Server-only modules that use computed process.env[name] for
        // private vars are fine and must not trip this rule.
        if (!source.includes("NEXT_PUBLIC_")) continue;

        const lines = source.split("\n");
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (isCommentLine(line)) continue;
          // Match computed access: process.env[...] where ... is not a
          // literal string ending in a static identifier. We match the
          // bracket form specifically — process.env.NEXT_PUBLIC_FOO is fine.
          if (!/process\.env\s*\[/.test(line)) continue;
          // Skip the benign case where the key is a single string literal
          // (e.g., process.env["NEXT_PUBLIC_FOO"]). Next.js does inline
          // string-literal brackets. The dangerous form is variable keys.
          if (/process\.env\s*\[\s*['"`][A-Z0-9_]+['"`]\s*\]/.test(line)) continue;
          findings.push(
            mkFinding(
              "INFRA-011",
              "high",
              "Dynamic process.env[key] access for NEXT_PUBLIC_* var",
              "Next.js inlines NEXT_PUBLIC_* vars at build time only when accessed as static property references. Computed bracket access with a variable key is not statically analyzable, so the bundler leaves it as-is and the value resolves to undefined at runtime in the browser.",
              "At runtime in the browser, the env var resolves to undefined and any code that depends on it crashes. This typically shows up as a white screen on the first client render — the whole page breaks, not just the feature using the var. It builds cleanly and passes typecheck, so it ships silently to production.",
              "Replace the computed access with a direct static reference: `process.env.NEXT_PUBLIC_SUPABASE_URL` instead of `process.env[name]` or `process.env[key]`. Export each public var individually from your env module as its own static constant.",
              [{ file, line: i + 1, snippet: line.trim() }],
              { cwe: "CWE-1188" },
            ),
          );
        }
      }
      return findings;
    },
  },
];

// Touch-test to make sure parseEnvFile/readEnvFile are exported; some
// future infra rules will need them.
void readEnvFile;
void parseEnvFile;
