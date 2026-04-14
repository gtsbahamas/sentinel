import { safeReadFile } from "../../../utils/fs.js";
import fg from "fast-glob";
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
    domain: "input-injection",
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
  const files = await fg(["**/*.{ts,tsx,js,jsx}"], {
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
  return Promise.all(
    files.map(async (file) => ({ file, source: await safeReadFile(file) })),
  );
}

async function scanLines(
  model: ProjectModel,
  pattern: RegExp,
  makeFinding: (file: string, line: number, match: RegExpMatchArray) => Finding,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(model);
  for (const { file, source } of files) {
    const lines = source.split("\n");
    lines.forEach((line, idx) => {
      const match = line.match(pattern);
      if (match) findings.push(makeFinding(file, idx + 1, match));
    });
  }
  return findings;
}

export const inputInjectionRules: SecurityRule[] = [
  {
    id: "INPUT-001",
    domain: "input-injection",
    title: "dangerouslySetInnerHTML without sanitization",
    description: "React's dangerouslySetInnerHTML used without DOMPurify or equivalent",
    impact: "Your app renders user-supplied HTML without sanitization. An attacker can inject a script tag that runs in other users' browsers, stealing their session cookies or redirecting them to a phishing site.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79", owasp: "A03:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      for (const { file, source } of files) {
        if (!/dangerouslySetInnerHTML/.test(source)) continue;
        const hasSanitizer = /DOMPurify|sanitize-html|isomorphic-dompurify/.test(source);
        if (hasSanitizer) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (/dangerouslySetInnerHTML/.test(line)) {
            findings.push(
              mkFinding(
                "INPUT-001",
                "critical",
                "dangerouslySetInnerHTML without sanitizer",
                "React component renders raw HTML without sanitization.",
                "Your app renders user-supplied HTML without sanitization. An attacker can inject a script tag that runs in other users' browsers, stealing their session cookies or redirecting them to a phishing site.",
                "Sanitize input with DOMPurify before passing to dangerouslySetInnerHTML.",
                [{ file, line: idx + 1, snippet: line.trim() }],
                { cwe: "CWE-79", owasp: "A03:2021" },
              ),
            );
          }
        });
      }
      return findings;
    },
  },

  {
    id: "INPUT-002",
    domain: "input-injection",
    title: "innerHTML assignment with non-literal value",
    description: "Direct innerHTML assignment bypasses React's escaping",
    impact: "Your app assigns user input directly to innerHTML, bypassing React's built-in XSS protection. An attacker can inject executable JavaScript that runs with full access to the page.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    check(model) {
      return scanLines(
        model,
        /\.innerHTML\s*=\s*(?!["'])/,
        (file, line, match) =>
          mkFinding(
            "INPUT-002",
            "high",
            "innerHTML assignment with variable",
            "Setting innerHTML to a non-literal value can introduce XSS.",
            "Your app assigns user input directly to innerHTML, bypassing React's built-in XSS protection. An attacker can inject executable JavaScript that runs with full access to the page.",
            "Use textContent for text, or sanitize HTML before assignment.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-79" },
          ),
      );
    },
  },

  {
    id: "INPUT-003",
    domain: "input-injection",
    title: "SQL string concatenation",
    description: "Template literal used in raw SQL query",
    impact: "Your app builds SQL queries by concatenating user input into the query string. An attacker can inject their own SQL commands to read, modify, or delete any data in your database.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-89", owasp: "A03:2021" },
    check(model) {
      return scanLines(
        model,
        /\.(query|execute|raw)\s*\(\s*`[^`]*\$\{/,
        (file, line, match) =>
          mkFinding(
            "INPUT-003",
            "critical",
            "SQL query built with template literal",
            "Interpolating values into SQL strings allows injection.",
            "Your app builds SQL queries by concatenating user input into the query string. An attacker can inject their own SQL commands to read, modify, or delete any data in your database.",
            "Use parameterized queries. Pass values as a second argument to query().",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-89", owasp: "A03:2021" },
          ),
      );
    },
  },

  {
    id: "INPUT-004",
    domain: "input-injection",
    title: "eval or Function constructor used",
    description: "Dynamic code evaluation is a code injection vector",
    impact: "Your app passes user input to eval() or the Function constructor, which executes it as code. An attacker can run any JavaScript on your server, including reading files, accessing databases, or installing backdoors.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-95" },
    check(model) {
      return scanLines(
        model,
        /\beval\s*\(|\bnew\s+Function\s*\(/,
        (file, line, match) =>
          mkFinding(
            "INPUT-004",
            "critical",
            "Dynamic code evaluation",
            "eval and Function constructors execute arbitrary code.",
            "Your app passes user input to eval() or the Function constructor, which executes it as code. An attacker can run any JavaScript on your server, including reading files, accessing databases, or installing backdoors.",
            "Refactor to avoid dynamic evaluation. Use JSON.parse for data.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-95" },
          ),
      );
    },
  },

  {
    id: "INPUT-005",
    domain: "input-injection",
    title: "API route missing request body validation",
    description: "Mutation endpoint accepts body without schema validation",
    impact: "Your API endpoint accepts data without validating its shape or type. An attacker can send unexpected fields, wrong types, or oversized payloads to trigger errors, bypass logic, or corrupt your database.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-20", owasp: "A03:2021" },
    check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        const isMutation = ["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method);
        if (isMutation && !endpoint.hasValidation) {
          findings.push(
            mkFinding(
              "INPUT-005",
              "high",
              `${endpoint.method} ${endpoint.path} missing body validation`,
              "API route does not validate request body against a schema.",
              "Your API endpoint accepts data without validating its shape or type. An attacker can send unexpected fields, wrong types, or oversized payloads to trigger errors, bypass logic, or corrupt your database.",
              "Add Zod or Yup schema and call .parse() on the request body.",
              [{ file: endpoint.file }],
              { cwe: "CWE-20", owasp: "A03:2021" },
            ),
          );
        }
      }
      return findings;
    },
  },

  {
    id: "INPUT-006",
    domain: "input-injection",
    title: "window.location assigned from untrusted source",
    description: "Open redirect when location is set from user-controlled input",
    impact: "Your app redirects users based on a URL from the request. An attacker can craft a link to your site that redirects victims to a phishing page, exploiting your domain's trust.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-601" },
    check(model) {
      return scanLines(
        model,
        /(window\.location|location\.href)\s*=\s*(?!\s*["'`\/])[^;]/,
        (file, line, match) =>
          mkFinding(
            "INPUT-006",
            "high",
            "Location assignment from variable",
            "Assigning location from a variable without validation enables open redirect.",
            "Your app redirects users based on a URL from the request. An attacker can craft a link to your site that redirects victims to a phishing page, exploiting your domain's trust.",
            "Validate the URL against an allowlist before redirecting.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-601" },
          ),
      );
    },
  },

  {
    id: "INPUT-007",
    domain: "input-injection",
    title: "document.write used",
    description: "document.write is an XSS vector",
    impact: "Your app uses document.write, which overwrites the page content and can execute injected scripts. An attacker who controls any input rendered by document.write gets full XSS.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-79" },
    check(model) {
      return scanLines(
        model,
        /document\.write\s*\(/,
        (file, line, match) =>
          mkFinding(
            "INPUT-007",
            "medium",
            "document.write used",
            "document.write bypasses React's escaping and can introduce XSS.",
            "Your app uses document.write, which overwrites the page content and can execute injected scripts. An attacker who controls any input rendered by document.write gets full XSS.",
            "Use React state or refs to update the DOM.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-79" },
          ),
      );
    },
  },

  {
    id: "INPUT-008",
    domain: "input-injection",
    title: "Shell command constructed with template string",
    description: "exec/spawn called with interpolated user input",
    impact: "Your app passes user input into a shell command. An attacker can inject shell metacharacters to execute arbitrary system commands on your server.",
    severity: "critical",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-78" },
    check(model) {
      return scanLines(
        model,
        /(exec|spawn|execSync|spawnSync)\s*\(\s*`[^`]*\$\{/,
        (file, line, match) =>
          mkFinding(
            "INPUT-008",
            "critical",
            "Shell command with interpolated value",
            "Building shell commands with template literals enables command injection.",
            "Your app passes user input into a shell command. An attacker can inject shell metacharacters to execute arbitrary system commands on your server.",
            "Use the array form of spawn() and pass arguments as array elements.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-78" },
          ),
      );
    },
  },

  {
    id: "INPUT-009",
    domain: "input-injection",
    title: "URL parameter passed to fetch (SSRF risk)",
    description: "fetch() called with a URL derived from request input",
    impact: "Your app makes HTTP requests to URLs derived from user input. An attacker can redirect those requests to internal services behind your firewall, accessing admin panels, cloud metadata, or databases.",
    severity: "high",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-918" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      for (const { file, source } of files) {
        if (!/fetch\s*\(/.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (/fetch\s*\(\s*(req\.|request\.|searchParams|params\.|body\.)/.test(line)) {
            findings.push(
              mkFinding(
                "INPUT-009",
                "high",
                "fetch called with request-derived URL",
                "SSRF is possible when fetch targets are controlled by user input.",
                "Your app makes HTTP requests to URLs derived from user input. An attacker can redirect those requests to internal services behind your firewall, accessing admin panels, cloud metadata, or databases.",
                "Validate URLs against an allowlist of hosts before calling fetch.",
                [{ file, line: idx + 1, snippet: line.trim() }],
                { cwe: "CWE-918" },
              ),
            );
          }
        });
      }
      return findings;
    },
  },

  {
    id: "INPUT-010",
    domain: "input-injection",
    title: "Regex constructed from user input",
    description: "new RegExp() called with a non-literal value",
    impact: "Your app constructs regular expressions from user input. An attacker can craft a pattern that causes catastrophic backtracking, freezing your server for seconds or minutes per request.",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-1333" },
    check(model) {
      return scanLines(
        model,
        /new\s+RegExp\s*\(\s*(?!["'/])/,
        (file, line, match) =>
          mkFinding(
            "INPUT-010",
            "medium",
            "Dynamic regex construction",
            "Building a regex from user input can cause ReDoS attacks.",
            "Your app constructs regular expressions from user input. An attacker can craft a pattern that causes catastrophic backtracking, freezing your server for seconds or minutes per request.",
            "Escape regex metacharacters, or use simple string matching.",
            [{ file, line, snippet: match[0] }],
            { cwe: "CWE-1333" },
          ),
      );
    },
  },
];
