import fg from "fast-glob";
import { safeReadFile } from "../../../utils/fs.js";
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
    domain: "logging-monitoring",
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

const SENSITIVE_KEYS = /\b(password|passwd|pwd|token|secret|apiKey|api_key|authorization|cookie|session|privateKey|jwt|refreshToken|accessToken)\b/i;

export const loggingMonitoringRules: SecurityRule[] = [
  {
    id: "LOG-001",
    domain: "logging-monitoring",
    title: "Sensitive value in log call",
    description: "console/logger call references a sensitive variable name",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-532" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const logCall = /(console\.(log|info|warn|error|debug)|logger\.(info|warn|error|debug)|pino\.[a-z]+)\s*\(([^)]+)\)/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          const m = line.match(logCall);
          if (!m) return;
          const args = m[4];
          if (!SENSITIVE_KEYS.test(args)) return;
          findings.push(
            mkFinding(
              "LOG-001",
              "high",
              "Sensitive value passed to log",
              "Log aggregators (Datadog, Sentry, CloudWatch) index log content. Secrets in logs become searchable.",
              "Redact sensitive fields before logging. Use a logger config that strips keys like `password` and `token`.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-532" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "LOG-002",
    domain: "logging-monitoring",
    title: "console.log in API route handler",
    description: "Route handler uses console.log instead of a structured logger",
    severity: "low",
    appliesTo: ["nextjs-supabase"],
    references: {},
    async check(model) {
      const findings: Finding[] = [];
      const structuredLoggerImport = /from\s+["'](pino|winston|bunyan|@logtail\/[\w-]+|roarr|loglevel)["']|import\s+logger\b/;
      for (const endpoint of model.endpoints) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        // If the file already imports a structured logger, assume console.* is
        // intentional (debug scaffolding) rather than a missing-logger issue.
        if (structuredLoggerImport.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!/console\.(log|debug|info)/.test(line)) return;
          findings.push(
            mkFinding(
              "LOG-002",
              "low",
              "console.log in API route",
              "console.log output is unstructured and loses request context in production log pipelines.",
              "Use a structured logger (pino, winston) with request/user context attached.",
              [{ file: endpoint.file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              {},
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "LOG-003",
    domain: "logging-monitoring",
    title: "Stack trace returned in API response",
    description: "Error message passed through to the client includes .stack",
    severity: "high",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: { cwe: "CWE-209" },
    async check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!/\b(?:return|throw|NextResponse\.json|res\.json|Response)\s*\(?.*error\.stack/.test(line)) return;
          findings.push(
            mkFinding(
              "LOG-003",
              "high",
              "Stack trace returned to client",
              "Exposing stack traces reveals file paths, dependency versions, and sometimes credentials from error messages.",
              "Return a generic error message with an ID the user can reference. Log the full stack server-side only.",
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
    id: "LOG-004",
    domain: "logging-monitoring",
    title: "Admin operation without audit log",
    description: "supabase.auth.admin or service-role write without an accompanying audit log call",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-778" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const adminOp = /supabase\.auth\.admin\.(deleteUser|updateUserById|createUser|generateLink)|service_role.*\.(delete|update|insert)/i;
      const auditCall = /audit|logEvent|trackEvent|captureEvent/i;
      for (const { file, source } of files) {
        if (!adminOp.test(source)) continue;
        if (auditCall.test(source)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!adminOp.test(line)) return;
          findings.push(
            mkFinding(
              "LOG-004",
              "medium",
              "Admin operation without audit trail",
              "Privileged operations must be logged for forensic response and compliance.",
              "Record who performed the action, when, and the target. Write to an append-only audit log table.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-778" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "LOG-005",
    domain: "logging-monitoring",
    title: "Unhandled promise rejection in route handler",
    description: "Async handler without a try/catch around the main body",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-391" },
    async check(model) {
      const findings: Finding[] = [];
      for (const endpoint of model.endpoints) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        // Heuristic: file contains `await` but zero `try {` blocks AND no
        // `.catch(` chain. Also skip if a global error handler / error boundary
        // import is present.
        if (!/\bawait\b/.test(source)) continue;
        if (/\btry\s*\{/.test(source)) continue;
        if (/\.catch\s*\(/.test(source)) continue;
        if (/errorHandler|withErrorHandler|asyncHandler|captureException/.test(source)) continue;
        findings.push(
          mkFinding(
            "LOG-005",
            "medium",
            "Async handler with no try/catch",
            "An unhandled rejection sends a generic 500 without being logged to your error tracker.",
            "Wrap the handler body in try/catch and forward errors to your observability pipeline (Sentry, etc.).",
            [{ file: endpoint.file }],
            { cwe: "CWE-391" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "LOG-006",
    domain: "logging-monitoring",
    title: "No error boundary in React tree",
    description: "App router does not define an error.tsx / ErrorBoundary",
    severity: "low",
    appliesTo: ["nextjs-supabase", "react-vite-supabase"],
    references: {},
    async check(model) {
      const findings: Finding[] = [];
      // 1. Conventional files
      const files = await fg(["**/error.tsx", "**/error.jsx", "**/*ErrorBoundary*.{ts,tsx,js,jsx}"], {
        cwd: model.meta.path,
        absolute: true,
        ignore: ["**/node_modules/**", "**/.next/**", "**/dist/**"],
      });
      if (files.length > 0) return findings;
      // 2. react-error-boundary dependency
      if (model.dependencies.some((d) => d.name === "react-error-boundary")) return findings;
      // 3. Custom boundary: any source file implementing componentDidCatch or
      //    getDerivedStateFromError.
      const sources = await walkSourceFiles(model);
      const hasCustomBoundary = sources.some(({ source }) =>
        /componentDidCatch\s*\(|getDerivedStateFromError\s*\(/.test(source),
      );
      if (hasCustomBoundary) return findings;
      findings.push(
        mkFinding(
          "LOG-006",
          "low",
          "No error boundary defined",
          "React errors without a boundary unmount the entire tree and can reveal component internals.",
          "Add an app-level error.tsx (Next.js) or ErrorBoundary component with a generic fallback.",
          [{ file: model.meta.path }],
          {},
        ),
      );
      return findings;
    },
  },

  {
    id: "LOG-007",
    domain: "logging-monitoring",
    title: "PII logged in plaintext",
    description: "Email, phone, or full name logged directly",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-359" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const piiLog = /console\.(log|info|warn|error|debug)\s*\([^)]*\b(email|phone|firstName|lastName|ssn|dob|birthdate)\b/i;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!piiLog.test(line)) return;
          findings.push(
            mkFinding(
              "LOG-007",
              "medium",
              "PII logged in plaintext",
              "Personally identifiable information in logs violates GDPR/CCPA and makes log aggregators a compliance liability.",
              "Hash or tokenize PII before logging, or log a non-reversible identifier instead.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-359" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "LOG-008",
    domain: "logging-monitoring",
    title: "Silenced error (empty catch block)",
    description: "catch block with no body or only a return",
    severity: "medium",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-390" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      const emptyCatch = /catch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!emptyCatch.test(line)) return;
          findings.push(
            mkFinding(
              "LOG-008",
              "medium",
              "Empty catch block",
              "Silent exception handling hides failures and makes incidents invisible to operators.",
              "At minimum, log the caught error with logger.error(). Re-throw if recovery is not possible.",
              [{ file, line: idx + 1, snippet: line.trim() }],
              { cwe: "CWE-390" },
            ),
          );
        });
      }
      return findings;
    },
  },

  {
    id: "LOG-009",
    domain: "logging-monitoring",
    title: "Authentication events not logged",
    description: "Login handler has no observable log of success/failure",
    severity: "medium",
    appliesTo: ["nextjs-supabase"],
    references: { cwe: "CWE-778" },
    async check(model) {
      const findings: Finding[] = [];
      const authRoutes = model.endpoints.filter((e) =>
        /login|signin|signup|register|forgot|reset|verify/i.test(e.path),
      );
      // "Structured" logging means a real logger import or audit call — not
      // console.log (which is itself flagged by LOG-002 as insufficient).
      const structuredLogger = /\blogger\.(info|warn|error|debug)\b|\bpino\s*\(|\baudit\s*\(|\btrack\s*\(|\bcaptureMessage\s*\(|from\s+["']pino["']|from\s+["']winston["']/;
      for (const endpoint of authRoutes) {
        const source = await safeReadFile(endpoint.file).catch(() => "");
        if (structuredLogger.test(source)) continue;
        findings.push(
          mkFinding(
            "LOG-009",
            "medium",
            `${endpoint.path} does not log auth events`,
            "Authentication events are a required audit trail for detecting credential stuffing and account takeover.",
            "Log login attempts (success and failure) with IP, user-agent, and user ID. Use a structured logger, not console.log.",
            [{ file: endpoint.file }],
            { cwe: "CWE-778" },
          ),
        );
      }
      return findings;
    },
  },

  {
    id: "LOG-010",
    domain: "logging-monitoring",
    title: "Debug flag forced on",
    description: "process.env.DEBUG or NODE_ENV === 'development' set at import time",
    severity: "low",
    appliesTo: ["nextjs-supabase", "react-vite-supabase", "generic-web"],
    references: { cwe: "CWE-489" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkSourceFiles(model);
      // Only flag hardcoded truthy assignments. `process.env.DEBUG = process.env.DEBUG || 'foo'`
      // and `process.env.DEBUG = someVar` are NOT flagged — the `debug` npm package
      // uses the env var legitimately. We only flag literal `true`/`'1'`/`'*'`/quoted
      // namespaces, forced NODE_ENV=development, or forced DEV/__DEV__ assignments.
      const re = /process\.env\.DEBUG\s*=\s*(?:true|["'](?:1|\*|[\w:*-]+)["'])|process\.env\.NODE_ENV\s*=\s*["']development["']|\b(?:__DEV__|DEV)\s*=\s*true\b/;
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (!re.test(line)) return;
          findings.push(
            mkFinding(
              "LOG-010",
              "low",
              "Debug flag forced on in source",
              "Debug flags should be configured per environment, not hardcoded.",
              "Remove the assignment and control debug output via environment configuration.",
              [{ file, line: idx + 1, snippet: line.trim().slice(0, 120) }],
              { cwe: "CWE-489" },
            ),
          );
        });
      }
      return findings;
    },
  },
];
