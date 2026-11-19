// Python framework-specific security rules.
//
// Earlier versions of sentinel only fired secrets-exposure / infrastructure
// rules on Python projects (SECRETS-003, SECRETS-006, SECRETS-008, INFRA-008).
// This module adds framework-aware rules covering the most common
// vibe-coder mistakes in Django and Flask:
//
//   - PY-DJANGO-001: `DEBUG = True` reachable in production settings.
//   - PY-DJANGO-002: hardcoded SECRET_KEY in settings.
//   - PY-DJANGO-003: `ALLOWED_HOSTS = ['*']` in settings.
//   - PY-FLASK-001: `app.run(debug=True)` in app code.
//   - PY-FLASK-002: hardcoded Flask `SECRET_KEY` assignment.
//   - PY-SQL-001: f-string or .format() interpolation inside a raw SQL string.
//
// These rules walk `.py` files directly (model.routes is currently empty for
// Python projects) and use line-by-line regex matching. The patterns are
// conservative: lines starting with `#` are skipped, and we only flag clear
// assignment forms (not test fixtures or inline comments about the bad
// pattern). Confidence is "high" for unambiguous matches, "medium" for
// patterns where the surrounding code could change meaning.

import fg from "fast-glob";
import { safeReadFile } from "../../../utils/fs.js";
import type { Finding, ProjectModel } from "../../../model/types.js";
import type { SecurityRule } from "../registry.js";

function mkFinding(
  ruleId: string,
  domain: Finding["domain"],
  severity: Finding["severity"],
  confidence: Finding["confidence"],
  title: string,
  description: string,
  impact: string,
  remediation: string,
  evidence: Finding["evidence"],
  refs: { cwe?: string; owasp?: string },
): Finding {
  return {
    id: `${ruleId}-${evidence[0]?.file ?? "x"}-${evidence[0]?.line ?? 0}`,
    domain,
    severity,
    confidence,
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

function isPyComment(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith("#");
}

async function walkPyFiles(
  model: ProjectModel,
): Promise<Array<{ file: string; source: string }>> {
  const files = await fg(["**/*.py"], {
    cwd: model.meta.path,
    absolute: true,
    ignore: [
      "**/node_modules/**",
      "**/.venv/**",
      "**/venv/**",
      "**/env/**",
      "**/.tox/**",
      "**/__pycache__/**",
      "**/dist/**",
      "**/build/**",
      "**/site-packages/**",
      // Skip test-y paths — fixtures often contain intentionally bad code.
      "**/tests/**",
      "**/test/**",
      "**/*_test.py",
      "**/test_*.py",
      // Skip migrations — generated, not hand-edited.
      "**/migrations/**",
    ],
  });
  return Promise.all(
    files.map(async (file) => ({ file, source: await safeReadFile(file) })),
  );
}

// Pattern: DEBUG = True (Django). Allow whitespace around =, but no other
// expression on the right (so DEBUG = os.environ.get('DEBUG') == 'True' is
// safe). Only match in settings*.py files where Django convention lives.
const DEBUG_TRUE_RE = /^\s*DEBUG\s*=\s*True\s*(?:#.*)?$/;

// Pattern: SECRET_KEY = "something". Tolerates single or double quotes and
// arbitrary content. We reject the os.environ form and the empty string.
const SECRET_KEY_LITERAL_RE = /^\s*SECRET_KEY\s*=\s*(['"])([^'"]{8,})\1/;

// Pattern: ALLOWED_HOSTS = ['*'] or ['*', ...]. Trips on any list literal
// containing a bare star string.
const ALLOWED_HOSTS_WILDCARD_RE = /^\s*ALLOWED_HOSTS\s*=.*\[\s*(['"])\*\1/;

// Pattern: app.run(debug=True) or .run(host=..., debug=True, ...).
// We match the kw form because `app.run(True)` is positional-host, not debug.
const FLASK_DEBUG_RUN_RE = /\.run\s*\([^)]*\bdebug\s*=\s*True\b/;

// Flask SECRET_KEY assignments: app.config['SECRET_KEY'] = 'literal' or
// app.secret_key = 'literal'.
const FLASK_SECRET_RE =
  /(?:\.config\s*\[\s*['"]SECRET_KEY['"]\s*\]|\.secret_key)\s*=\s*(['"])([^'"]{4,})\1/;

// f-string SQL: f"SELECT ..." or f"INSERT ...", where { } interpolation
// appears. Conservative: only flag known SQL verbs at the start of the
// string to avoid catching every f-string.
const FSTRING_SQL_RE =
  /\bf(['"])(?:SELECT|INSERT|UPDATE|DELETE|MERGE|DROP|ALTER)\b[^'"]*\{[^}]+\}[^'"]*\1/i;
// .format() SQL: "SELECT ... {} ...".format(...) — same verbs.
const FORMAT_SQL_RE =
  /(['"])(?:SELECT|INSERT|UPDATE|DELETE|MERGE|DROP|ALTER)\b[^'"]*\{[^}]*\}[^'"]*\1\.format\s*\(/i;
// String concat SQL: "SELECT ... " + variable
const CONCAT_SQL_RE =
  /(['"])(?:SELECT|INSERT|UPDATE|DELETE|MERGE|DROP|ALTER)\b[^'"]*\1\s*\+\s*\w+/i;

function isDjangoSettingsFile(file: string): boolean {
  // Conventional Django path: <project>/settings.py or settings/{base,prod}.py.
  return /(?:^|[/\\])settings(?:[/\\]\w+)?\.py$/i.test(file);
}

export const pythonFrameworkRules: SecurityRule[] = [
  {
    id: "PY-DJANGO-001",
    domain: "infrastructure",
    title: "Django DEBUG=True in settings",
    description:
      "Django settings.py has DEBUG = True. In production this leaks stack traces, settings, and SQL.",
    impact:
      "Django's debug mode renders detailed exception pages containing stack traces, environment variables, and the project's settings. Anyone who triggers an exception in production sees enough to take over the app.",
    severity: "critical",
    appliesTo: ["python"],
    references: { cwe: "CWE-489" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkPyFiles(model);
      for (const { file, source } of files) {
        if (!isDjangoSettingsFile(file)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (isPyComment(line)) return;
          if (!DEBUG_TRUE_RE.test(line)) return;
          findings.push(
            mkFinding(
              "PY-DJANGO-001",
              "infrastructure",
              "critical",
              "high",
              "Django DEBUG=True in settings",
              "DEBUG must be False in production settings.",
              "Django's debug mode renders detailed exception pages containing stack traces, environment variables, and the project's settings. Anyone who triggers an exception in production sees enough to take over the app.",
              "Set DEBUG = False, or read from env: `DEBUG = os.environ.get('DEBUG', '') == '1'`. Keep True only in local dev settings.",
              [{ file, line: idx + 1, snippet: line.trim() }],
              { cwe: "CWE-489" },
            ),
          );
        });
      }
      return findings;
    },
  },
  {
    id: "PY-DJANGO-002",
    domain: "secrets-exposure",
    title: "Django SECRET_KEY hardcoded in settings",
    description:
      "A literal string is assigned to SECRET_KEY. Should come from an environment variable.",
    impact:
      "Django uses SECRET_KEY to sign sessions, password reset tokens, CSRF tokens, and more. A hardcoded key committed to git leaks via the repo and can be used to forge sessions and reset passwords.",
    severity: "critical",
    appliesTo: ["python"],
    references: { cwe: "CWE-798" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkPyFiles(model);
      for (const { file, source } of files) {
        if (!isDjangoSettingsFile(file)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (isPyComment(line)) return;
          const m = line.match(SECRET_KEY_LITERAL_RE);
          if (!m) return;
          // Skip django-insecure-* placeholder keys — those are the
          // out-of-the-box manage.py startproject value and warrant a
          // medium-sev finding, not critical.
          const value = m[2];
          const isPlaceholder = value.startsWith("django-insecure-");
          findings.push(
            mkFinding(
              "PY-DJANGO-002",
              "secrets-exposure",
              isPlaceholder ? "medium" : "critical",
              "high",
              isPlaceholder
                ? "Django default SECRET_KEY still in settings"
                : "Django SECRET_KEY hardcoded in settings",
              "Hardcoded literal assigned to SECRET_KEY.",
              "Django uses SECRET_KEY to sign sessions, password reset tokens, CSRF tokens, and more. A hardcoded key committed to git leaks via the repo and can be used to forge sessions and reset passwords.",
              "Load from env: `SECRET_KEY = os.environ['DJANGO_SECRET_KEY']`. Rotate the existing value if it has been committed.",
              [{ file, line: idx + 1, snippet: line.trim() }],
              { cwe: "CWE-798" },
            ),
          );
        });
      }
      return findings;
    },
  },
  {
    id: "PY-DJANGO-003",
    domain: "infrastructure",
    title: "Django ALLOWED_HOSTS wildcard",
    description:
      "ALLOWED_HOSTS contains '*', accepting any Host header.",
    impact:
      "Django's ALLOWED_HOSTS protects against Host-header injection — used in password-reset link forgery and cache-poisoning attacks. A '*' bypass disables that protection.",
    severity: "high",
    appliesTo: ["python"],
    references: { cwe: "CWE-20" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkPyFiles(model);
      for (const { file, source } of files) {
        if (!isDjangoSettingsFile(file)) continue;
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (isPyComment(line)) return;
          if (!ALLOWED_HOSTS_WILDCARD_RE.test(line)) return;
          findings.push(
            mkFinding(
              "PY-DJANGO-003",
              "infrastructure",
              "high",
              "high",
              "Django ALLOWED_HOSTS = ['*']",
              "ALLOWED_HOSTS allows any Host header.",
              "Django's ALLOWED_HOSTS protects against Host-header injection — used in password-reset link forgery and cache-poisoning attacks. A '*' bypass disables that protection.",
              "Set ALLOWED_HOSTS to the specific domains the app serves: `ALLOWED_HOSTS = ['shipsafe.app', 'www.shipsafe.app']`.",
              [{ file, line: idx + 1, snippet: line.trim() }],
              { cwe: "CWE-20" },
            ),
          );
        });
      }
      return findings;
    },
  },
  {
    id: "PY-FLASK-001",
    domain: "infrastructure",
    title: "Flask app.run(debug=True)",
    description:
      "Flask's built-in dev server is running with debug=True, which exposes the Werkzeug debugger.",
    impact:
      "The Werkzeug debugger exposes an interactive Python console at /console — anyone who reaches that URL can execute arbitrary code on the server. Combined with weak DEBUG_PIN protection (or an attacker who can read /proc), this is a remote code execution path.",
    severity: "critical",
    appliesTo: ["python"],
    references: { cwe: "CWE-489", owasp: "A05:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkPyFiles(model);
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (isPyComment(line)) return;
          if (!FLASK_DEBUG_RUN_RE.test(line)) return;
          findings.push(
            mkFinding(
              "PY-FLASK-001",
              "infrastructure",
              "critical",
              "high",
              "Flask app.run(debug=True)",
              "Werkzeug debugger is exposed via debug=True.",
              "The Werkzeug debugger exposes an interactive Python console at /console — anyone who reaches that URL can execute arbitrary code on the server. Combined with weak DEBUG_PIN protection (or an attacker who can read /proc), this is a remote code execution path.",
              "Remove debug=True. Use a real WSGI server (gunicorn, uWSGI) in production. Local dev: gate debug=True on `os.environ.get('FLASK_ENV') == 'development'`.",
              [{ file, line: idx + 1, snippet: line.trim() }],
              { cwe: "CWE-489", owasp: "A05:2021" },
            ),
          );
        });
      }
      return findings;
    },
  },
  {
    id: "PY-FLASK-002",
    domain: "secrets-exposure",
    title: "Flask SECRET_KEY hardcoded",
    description:
      "app.secret_key or app.config['SECRET_KEY'] assigned a literal string.",
    impact:
      "Flask uses SECRET_KEY to sign session cookies. A hardcoded key in source means anyone with repo access can forge session cookies and impersonate any user.",
    severity: "critical",
    appliesTo: ["python"],
    references: { cwe: "CWE-798" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkPyFiles(model);
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (isPyComment(line)) return;
          if (!FLASK_SECRET_RE.test(line)) return;
          findings.push(
            mkFinding(
              "PY-FLASK-002",
              "secrets-exposure",
              "critical",
              "high",
              "Flask SECRET_KEY hardcoded",
              "Literal string assigned to Flask SECRET_KEY.",
              "Flask uses SECRET_KEY to sign session cookies. A hardcoded key in source means anyone with repo access can forge session cookies and impersonate any user.",
              "Load from env: `app.secret_key = os.environ['FLASK_SECRET_KEY']`. Rotate the committed value.",
              [{ file, line: idx + 1, snippet: line.trim() }],
              { cwe: "CWE-798" },
            ),
          );
        });
      }
      return findings;
    },
  },
  {
    id: "PY-SQL-001",
    domain: "input-injection",
    title: "SQL injection via string interpolation",
    description:
      "An f-string, .format() call, or `+` concatenation builds a SQL query with embedded variables.",
    impact:
      "Concatenating untrusted input into a SQL query is the canonical SQL injection vector. Even when wrapped in cursor.execute(), the query is built BEFORE parameterization — the DB sees the attacker's payload as code, not data.",
    severity: "high",
    appliesTo: ["python"],
    references: { cwe: "CWE-89", owasp: "A03:2021" },
    async check(model) {
      const findings: Finding[] = [];
      const files = await walkPyFiles(model);
      for (const { file, source } of files) {
        const lines = source.split("\n");
        lines.forEach((line, idx) => {
          if (isPyComment(line)) return;
          let pattern: string | null = null;
          if (FSTRING_SQL_RE.test(line)) pattern = "f-string";
          else if (FORMAT_SQL_RE.test(line)) pattern = ".format()";
          else if (CONCAT_SQL_RE.test(line)) pattern = "concatenation";
          if (!pattern) return;
          findings.push(
            mkFinding(
              "PY-SQL-001",
              "input-injection",
              "high",
              "medium",
              `SQL injection via ${pattern}`,
              `Raw SQL string built with ${pattern}.`,
              "Concatenating untrusted input into a SQL query is the canonical SQL injection vector. Even when wrapped in cursor.execute(), the query is built BEFORE parameterization — the DB sees the attacker's payload as code, not data.",
              "Use parameterized queries: `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`. With Django ORM, prefer Q objects or filter() over .raw(). With SQLAlchemy, use bound parameters.",
              [{ file, line: idx + 1, snippet: line.trim() }],
              { cwe: "CWE-89", owasp: "A03:2021" },
            ),
          );
        });
      }
      return findings;
    },
  },
];
