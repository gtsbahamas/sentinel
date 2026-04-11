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
    evidence,
    remediation,
    references: [refs.cwe, refs.owasp].filter(Boolean) as string[],
    layer: "rules",
    ruleId,
    cwe: refs.cwe,
    owasp: refs.owasp,
  };
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
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-319" },
    check(model) {
      const findings: Finding[] = [];
      const tlsDeploys = new Set(["vercel", "cloudflare", "fly"]);
      const isTlsDeploy = model.meta.deployTarget !== null && tlsDeploys.has(model.meta.deployTarget);
      const missing = !model.infra.securityHeaders["strict-transport-security"];
      if (isTlsDeploy && missing) {
        findings.push(
          mkFinding(
            "INFRA-002",
            "high",
            "No Strict-Transport-Security header",
            "HSTS prevents downgrade attacks to plain HTTP and cookie leakage on the first request of a session.",
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
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-614" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const setCookieRe = /cookies\s*\(\s*\)\s*\.set|response\.cookies\.set|Set-Cookie|res\.cookie\s*\(/;
      for (const { file, source } of files) {
        if (!setCookieRe.test(source)) continue;
        // Only flag if the file is also using `secure: false` or simply has
        // no `secure` mention at all alongside a cookie set.
        if (/secure\s*:\s*true/.test(source)) continue;
        if (/sameSite\s*:\s*["']strict["']/.test(source) && /httpOnly\s*:\s*true/.test(source)) {
          // still want Secure in prod, but less severe if other hardening
          // is present. Keep the finding.
        }
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!setCookieRe.test(line)) return;
          findings.push(
            mkFinding(
              "INFRA-005",
              "high",
              "Cookie set without Secure flag",
              "Cookies without Secure can be sent over plain HTTP and captured by a network attacker.",
              "Set `secure: true` and `httpOnly: true` and `sameSite: 'lax'` (or 'strict') on all session cookies.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-614" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "INFRA-006",
    domain: "infrastructure",
    title: "HTTP origin allowed in fetch/axios/CORS config",
    description: "Plain http:// URL in source or config",
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
          if (/\/\/|\/\*/.test(line.trim().slice(0, 2))) return;
          findings.push(
            mkFinding(
              "INFRA-006",
              "medium",
              "Plain HTTP URL in source",
              "HTTP connections are subject to MITM injection and can leak credentials.",
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
    severity: "critical",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-312" },
    check(model) {
      const findings: Finding[] = [];
      const offenders = [".env", ".env.production", ".env.local"];
      const gitignorePath = join(model.meta.path, ".gitignore");
      const gitignored = existsSync(gitignorePath)
        ? new Set(
            readFileSync(gitignorePath, "utf-8")
              .split("\n")
              .map((l) => l.trim()),
          )
        : new Set<string>();
      for (const f of offenders) {
        const full = join(model.meta.path, f);
        if (!existsSync(full)) continue;
        const ignored = gitignored.has(f) || gitignored.has(`${f}/`) || gitignored.has(".env*") || gitignored.has(".env*.local");
        if (ignored) continue;
        findings.push(
          mkFinding(
            "INFRA-008",
            "critical",
            `${f} is present and not gitignored`,
            "Committing env files ships secrets into the repo permanently.",
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
            "Set `enable_confirmations = true` under `[auth.email]` in supabase/config.toml.",
            [{ file: cfg.file }],
            { cwe: "CWE-287" },
          ),
        );
      }
      return findings;
    },
  },
];

// Touch-test to make sure parseEnvFile/readEnvFile are exported; some
// future infra rules will need them.
void readEnvFile;
void parseEnvFile;
