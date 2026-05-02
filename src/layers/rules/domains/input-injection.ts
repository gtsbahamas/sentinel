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
    async check(model) {
      // The previous regex `\beval\s*\(` matched comments like
      //   // safe expression evaluator using expr-eval (no arbitrary ...
      // because `eval` after `expr-` is a word-boundary match and `\s*\(`
      // matches ` (` two chars later. All 10 v0.1.2 high+critical findings
      // for this rule were FPs of that shape (expr-eval library + comment).
      //
      // Refinements:
      //   1. Skip comment lines entirely (// and /* */).
      //   2. Require that the literal token immediately preceding `(` be
      //      `eval` itself, not part of a hyphenated identifier like
      //      `expr-eval`. We disallow `-` directly before `eval`.
      //   3. Allow `globalThis.eval(` and `window.eval(` as positive matches.
      //   4. Also match `Function(` (capital F, as constructor) which the
      //      existing rule already covered via `new Function (`.
      //   5. Skip declarations: `function evaluate(` / `evaluate(` method
      //      definitions are not eval calls.
      //   6. Skip standard test/migration paths.
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      // Strict: word-boundary on BOTH sides — must be eval not part of a
      // longer word. Forbid `-` directly before (so expr-eval doesn't match).
      // Allow optional namespace (globalThis., window.) preceding.
      const evalCall = /(?<![\w\-.$])(?:globalThis\.|window\.)?eval\s*\(/;
      const newFunctionCall = /\bnew\s+Function\s*\(/;
      for (const { file, source } of files) {
        if (/\/(test|tests|__tests__|__mocks__|migrations|seed|seeds|fixtures|e2e|spec)\//i.test(file)) continue;
        if (/\.(test|spec)\.(ts|tsx|js|jsx|mjs|cjs)$/i.test(file)) continue;

        const lines = source.split("\n");
        // Track block comment state so /* ... eval ( ... */ across multiple
        // lines doesn't trip the rule.
        let inBlockComment = false;
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          const trim = line.trim();
          // Block-comment tracking
          if (inBlockComment) {
            if (trim.includes("*/")) inBlockComment = false;
            continue;
          }
          if (trim.startsWith("/*")) {
            if (!trim.includes("*/")) inBlockComment = true;
            continue;
          }
          if (trim.startsWith("//") || trim.startsWith("*")) continue;

          // Strip the inline-comment portion of the line so `// eval (` mid-line
          // doesn't match either.
          const codeOnly = line.replace(/\/\/.*$/, "");

          let match: RegExpMatchArray | null = null;
          let kind: "eval" | "function" | null = null;
          const m1 = codeOnly.match(evalCall);
          if (m1) {
            // Skip method/function definitions: `function evaluate(`,
            // `private evaluateExpression(` etc. The negative lookbehind on
            // word chars already covers the longer-identifier case; the
            // remaining ambiguity is bare `eval(` inside expressions.
            // Also skip uses of eval as a property KEY or string lookup:
            // `obj.eval = ...`, `import { eval } from`.
            // Heuristic: treat `eval(` as a real call only if the chars
            // before are an expression boundary or a namespace dot.
            const idx = m1.index ?? 0;
            const before = codeOnly.slice(Math.max(0, idx - 4), idx);
            if (/-eval$/.test(before)) continue;
            if (/^\s*(function|class|interface|type|enum)\s/.test(codeOnly)) continue;
            // method definition or property: `evaluate(` with a leading `.`
            // already excluded. Still skip `: eval(` (object destructuring).
            match = m1;
            kind = "eval";
          } else {
            const m2 = codeOnly.match(newFunctionCall);
            if (m2) {
              match = m2;
              kind = "function";
            }
          }
          if (!match || !kind) continue;

          findings.push(
            mkFinding(
              "INPUT-004",
              "critical",
              "Dynamic code evaluation",
              "eval and Function constructors execute arbitrary code.",
              "Your app passes user input to eval() or the Function constructor, which executes it as code. An attacker can run any JavaScript on your server, including reading files, accessing databases, or installing backdoors.",
              "Refactor to avoid dynamic evaluation. Use JSON.parse for data.",
              [{ file, line: i + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-95" },
            ),
          );
        }
      }
      return findings;
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
    async check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        const isMutation = ["POST", "PUT", "PATCH", "DELETE"].includes(endpoint.method);
        if (!isMutation) continue;
        if (endpoint.hasValidation) continue;

        // Read source so we can apply structural skips. The cost is small:
        // mutations are a small subset of all endpoints in any real project.
        const source = await safeReadFile(endpoint.file).catch(() => "");
        if (!source.trim()) continue; // empty/unreadable file — skip phantom

        // v0.1.4: 404-stub routes don't process bodies. Catches the same
        // catch-all template routes AUTH-001 skips: `[entity]/route.ts`
        // with default case returning 404 and no DB write.
        const is404Stub =
          /status:\s*404\b|status\s*:\s*404\b/.test(source) &&
          /(?:Unknown\s+entity|Not\s+found|404)/i.test(source) &&
          !/\.from\s*\(/.test(source) &&
          !/await\s+\w+\.(?:insert|update|delete|upsert|rpc)\s*\(/.test(source);
        if (is404Stub) continue;

        // Skip 1: endpoint reads no body. Many "actions" derive everything
        // from authenticated session (cancel-subscription, billing-portal,
        // refresh-token, refresh, sign-out). If there's no body read, there
        // is no body to validate.
        //
        // Body-read evidence:
        //   - req/request.json() / .formData() / .text() / .arrayBuffer() / .blob()
        //   - direct property access on `req.body` / `request.body`
        //   - `await body()` from formData/text helpers
        // Iter-5 fix: removed the over-broad `body|payload|input|args|params:`
        // arg-name match — that was matching `({ params }: ...)` destructures
        // and `args` in completely unrelated function signatures, so every
        // POST handler appeared to "read a body" and thus stayed in scope.
        // v0.1.4: also recognize the modern Next.js patterns where the
        // request is destructured from arg or named differently (e.g. `_req`
        // or just `request`), and where formData is awaited via `await
        // request.formData()` patterns the iter-5 regex missed.
        const readsBody =
          /\b(?:req|request|_req)\s*\.\s*(?:json|formData|text|arrayBuffer|blob)\s*\(/i.test(source) ||
          /\b(?:req|request|_req)\s*\.\s*body\b/i.test(source) ||
          /\bawait\s+(?:req|request|_req)\s*\.\s*json\b/i.test(source) ||
          /const\s*\{[^}]+\}\s*=\s*await\s+(?:req|request|_req)\s*\.\s*json/.test(source);
        if (!readsBody) continue;

        // Skip 2: webhook endpoints. Path includes /webhook(s) AND the file
        // performs HMAC signature verification (Stripe constructEvent,
        // createHmac+timingSafeEqual, verifyWebhook helpers, Inngest's
        // serve handler, Svix's verify, etc). The signature IS the validation.
        const isWebhookPath = /\/webhooks?\b|\/inngest\b|\/svix\b/i.test(endpoint.path);
        const hasSignatureCheck =
          /constructEvent\s*\(/.test(source) || // Stripe
          /\bverifyWebhook\b/i.test(source) ||
          /\bsvix\b/i.test(source) ||
          /\bInngest\b/.test(source) ||
          (/createHmac\s*\(/.test(source) && /timingSafeEqual/.test(source)) ||
          /\.verify\s*\(\s*[^,]*,[^,)]*signature/i.test(source);
        if (isWebhookPath && hasSignatureCheck) continue;

        // Skip 3: endpoint performs explicit per-field validation. The
        // hasValidation flag in recon only catches zod/yup/joi/.parse/.validate
        // helpers; many real codebases hand-roll the equivalent with explicit
        // required-field checks. If the file has BOTH a body-read and
        // multiple presence/typeof checks, treat it as adequately validated.
        // Heuristic: count required-field guards.
        const requiredFieldChecks = [
          /\bif\s*\(\s*!\s*\w+\s*\)\s*[\{return]/g, // if (!field) return / { ... }
          /\bif\s*\(\s*typeof\s+\w+\s*!==\s*["']/g, // if (typeof x !== 'string')
          /\bif\s*\(\s*!\s*Array\.isArray\s*\(/g, // if (!Array.isArray(x))
          /\.length\s*===\s*0\s*\)/g, // if (arr.length === 0)
          /\b(?:return|throw)\s+(?:new\s+)?\w*[Ee]rror\s*\(/g, // throw new Error(
        ];
        let guardCount = 0;
        for (const re of requiredFieldChecks) {
          const matches = source.match(re);
          if (matches) guardCount += matches.length;
        }
        // 3+ guards across body-reading endpoint → assume validation present.
        // Iter-5 lowered from 4 to 3 because verifier consistently dismissed
        // endpoints with 2-3 explicit field guards as "adequate validation"
        // even though they didn't import a schema lib.
        if (guardCount >= 3) continue;

        // Skip 4: comment-line-only matches and 410-stub deprecated routes.
        if (/status:\s*410\b|\.status\(\s*410\s*\)/.test(source)) continue;

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
