# Sentinel - Security Agent CLI Design

**Date:** 2026-04-10
**Status:** Design approved, Phase 1 MVP specced
**Author:** Ty Wells (design with Claude)

## Overview

Sentinel is a CLI-based security assessment tool that audits codebases for vulnerabilities across ten security domains. It combines deterministic rule-based scanning with optional AI-powered semantic analysis and optional active probing of running applications. Built for Ty's Next.js + Supabase portfolio as the primary target, with extensibility for other stacks.

The tool exists because a one-hour penetration test on one project surfaced critical findings (stored XSS, leaked secrets, file upload weaknesses, rate limiting gaps) that a bad actor with more time would extend across the full attack surface. Sentinel automates this continuous coverage across all projects.

## Inspiration and Prior Art

- **Mythos-jr** (github.com/m2ai-portfolio/mythos-jr): Defensive security agent built on Claude Agent SDK. Demonstrated the host/worker pattern, hard barriers over soft constraints, and lesson-to-code traceability. Sentinel borrows the hardening philosophy but is a standalone CLI rather than an A2A worker.
- **Claude Mythos Preview System Card**: Documented how advanced AI models can be used for real-world vulnerability discovery. Sentinel's AI layer design reflects the lessons about scoped prompts, validated outputs, and isolation.
- **Pentest findings (2026-04-09)**: Real vulnerabilities from a live assessment seeded the initial rule set, but Sentinel covers the full CISSP/CEH/Sec+ domain map, not just what that hour-long test surfaced.

## Design Decisions

| Decision | Choice | Reasoning |
|----------|--------|-----------|
| Execution model | Hybrid: static scan + optional active probe | Static catches code-level issues; probe confirms runtime behavior |
| Target surface | Next.js + Supabase first, extensible | Deep coverage of owned stack beats shallow generic coverage |
| AI strategy | Hybrid: rules first, AI second (optional) | Deterministic pass is fast/free; AI pass for semantic depth only when needed |
| Output formats | Terminal + HTML + JSON | CLI usability, sharing, and programmatic consumption all matter |
| Active probe | Configurable aggression levels (passive/standard/intrusive) | User authorizes scope explicitly; safe defaults prevent accidents |
| Domain taxonomy | Hybrid: OWASP + kill-chain + CISSP | Combines practical web-app coverage with full security breadth |
| Architecture | Layered pipeline (Recon → Rules → AI → Probe) | Each layer independently useful, shared ProjectModel as backbone |
| Language | TypeScript (ESM, Node 20+) | Matches target stack, shares AST tooling, matches mythos-jr pattern |
| Build order | Phase 1 MVP covers 4 domains with rules only | Prove value before investing in AI costs or probe authorization complexity |

## Goals

- Catch the full range of security issues a competent pentester would find, across all ten domains
- Run against any of Ty's ~100 projects with zero per-project setup beyond `.sentinelrc.json`
- Execute deterministic checks (rules layer) in under 15 seconds on a typical project
- Keep AI token costs bounded and configurable, never spiral on large codebases
- Provide actionable findings with file paths, line numbers, evidence, and remediation
- Never modify, execute, or import target project code during scanning
- Require explicit authorization for any active probing, with enforced rate limits and cleanup

## Non-Goals

- Supporting frameworks outside Next.js + Supabase in Phase 1 (extensible, not built)
- Replacing paid commercial scanners (Snyk, Veracode, Checkmarx) for compliance use cases
- Running without human review of findings (this is assistive tooling, not autonomous remediation)
- Providing a hosted SaaS version (local CLI only)
- Automatically fixing vulnerabilities (reporting only; remediation is the operator's responsibility)
- Offensive security tooling (the CEH authorization model applies; only scan what you own)

---

## Architecture

### Layered Pipeline

Four layers run in sequence, each enriching a shared `ProjectModel`:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Recon     │ -> │    Rules    │ -> │     AI      │ -> │    Probe    │
│  (always)   │    │  (always)   │    │  (--ai)     │    │  (--target) │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      |                  |                  |                   |
      v                  v                  v                   v
  ProjectModel      +Findings          +Findings           +Findings
  (discovered)      (deterministic)    (semantic)          (confirmed)
```

Layers are independent: Rules can run without AI or Probe. AI can run without Probe. Probe requires Recon + Rules context to know what to target but not AI.

### ProjectModel (Core Data Structure)

The single source of truth that flows through every layer. Defined in `src/model/types.ts`.

```typescript
interface ProjectModel {
  meta: {
    name: string;
    path: string;
    stack: StackProfile;
    packageManager: "pnpm" | "npm" | "yarn";
    language: "typescript" | "javascript";
    framework: string;
    deployTarget: string | null;
  };

  routes: Route[];
  endpoints: ApiEndpoint[];
  fileUploads: UploadHandler[];
  authFlows: AuthFlow[];
  dataModels: DataModel[];
  dependencies: Dependency[];
  envVars: EnvVar[];
  staticAssets: AssetRef[];

  findings: Finding[];
}

interface Finding {
  id: string;
  domain: SecurityDomain;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "confirmed" | "high" | "medium" | "low";
  title: string;
  description: string;
  evidence: Evidence[];
  remediation: string;
  references: string[];
  layer: "rules" | "ai" | "probe";
  cwe?: string;
  owasp?: string;
}

type SecurityDomain =
  | "secrets-exposure"
  | "input-injection"
  | "auth-access-control"
  | "file-upload"
  | "api-security"
  | "cryptography"
  | "supply-chain"
  | "infrastructure"
  | "business-logic"
  | "logging-monitoring";

type StackProfile = "nextjs-supabase" | "react-vite-supabase" | "generic-web";
```

Findings carry both a `confidence` level and a `layer` source. This preserves the distinction between "the code pattern looks vulnerable" (rules, medium confidence) and "the payload reflected back when we sent it" (probe, confirmed).

### Security Domain Taxonomy

Ten domains covering the CISSP/CEH/Sec+ application security spectrum:

| Domain | Covers |
|--------|--------|
| **Secrets & Exposure** | Client-side leaks, env vars, bundle scanning, git history, hardcoded credentials |
| **Input & Injection** | XSS (stored, reflected, DOM), SQL injection, command injection, template injection, SSRF |
| **Auth & Access Control** | Authentication, authorization, IDOR/BOLA, privilege escalation, JWT/session handling |
| **File Upload** | Upload validation, MIME checks, storage isolation, path traversal, zip slip |
| **API Security** | Rate limiting, mass assignment, error leakage, pagination, versioning, CORS scope |
| **Cryptography** | TLS config, hashing algorithms, key management, weak random, JWT algorithm choices |
| **Supply Chain** | Dependency vulns, typosquatting, lockfile integrity, build pipeline, postinstall risks |
| **Infrastructure** | Security headers, CSP, CORS, DNS, deployment config, serverless misconfig |
| **Business Logic** | Race conditions, state manipulation, workflow bypass, enumeration, idempotency |
| **Logging & Monitoring** | Audit trails, error handling, sensitive data in logs, alerting gaps |

---

## Layer 1: Recon

Runs first, always. No AI, no network. Pure filesystem analysis. Builds the ProjectModel.

### Responsibilities

- Detect stack from `package.json`, framework config files, lockfile type
- Parse router (App Router `app/` tree, `pages/`, or explicit route definitions) to discover every route
- AST-walk source files to find API endpoints, `fetch()` calls, form handlers, file upload inputs, auth checks, middleware chains
- Read Supabase config for RLS policies, storage bucket settings, edge function definitions
- Read deployment config (`vercel.json`, `wrangler.toml`) for infrastructure surface
- Parse `.env.example` and grep source for `process.env` / `import.meta.env` references
- Build dependency tree with versions from lockfile
- Never read actual `.env` files (only check existence and gitignore status)

### Discoverer Modules

Each responsibility is a module in `src/layers/recon/`:

- `stack-detector.ts` - Identifies framework, package manager, deploy target
- `route-discovery.ts` - Parses routing conventions
- `endpoint-discovery.ts` - Finds API endpoints, request/response shapes
- `auth-discovery.ts` - Maps auth flows, middleware chains, JWT config
- `upload-discovery.ts` - Finds file upload handlers, validation, storage
- `env-discovery.ts` - Maps env var usage, client exposure
- `dep-discovery.ts` - Dependency tree, versions, lockfile analysis

### Output

A fully populated `ProjectModel` with `findings: []`. Time budget: under 10 seconds on a typical Next.js project.

---

## Layer 2: Rules Engine

Deterministic checks against the ProjectModel. No AI, no network.

### Rule Structure

```typescript
interface SecurityRule {
  id: string;                    // "SECRETS-001"
  domain: SecurityDomain;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  check: (model: ProjectModel) => Finding[];
  appliesTo: StackProfile[];
  references: {
    cwe?: string;
    owasp?: string;
    external?: string[];
  };
}
```

### Phase 1 MVP Rules

Four domains are in scope for MVP. Each rule below must be implemented.

#### Secrets & Exposure

| Rule ID | Description | Severity |
|---------|-------------|----------|
| SECRETS-001 | Service role key / admin token referenced in client-side code | critical |
| SECRETS-002 | API keys matching known provider patterns in source files | critical |
| SECRETS-003 | `.env` file committed to git or not in `.gitignore` | critical |
| SECRETS-004 | Hardcoded credentials in source (password, apiKey, token assigned to string literals) | high |
| SECRETS-005 | `NEXT_PUBLIC_` prefix used with variables matching secret patterns | high |
| SECRETS-006 | Secrets or tokens referenced in git history (requires `--git-history` flag) | high |
| SECRETS-007 | Developer comments containing credentials, tokens, or internal URLs | medium |
| SECRETS-008 | Environment variables referenced in source but missing from `.env.example` | low |
| SECRETS-009 | Large JS bundles not gitignored (`dist/`, `.next/`) | info |

#### Input & Injection

| Rule ID | Description | Severity |
|---------|-------------|----------|
| INPUT-001 | `dangerouslySetInnerHTML` used without DOMPurify or equivalent sanitizer | critical |
| INPUT-002 | `innerHTML` assignment with non-literal value | high |
| INPUT-003 | SQL string concatenation (template literals with user input) | critical |
| INPUT-004 | `eval()`, `new Function()`, or `Function()` constructor used anywhere | critical |
| INPUT-005 | API route handler missing Zod/Yup/Joi validation on request body | high |
| INPUT-006 | User input passed to `window.location` or `location.href` without validation | high |
| INPUT-007 | `document.write()` used anywhere | medium |
| INPUT-008 | Template strings with user input passed to shell commands (`exec`, `spawn`) | critical |
| INPUT-009 | URL parameters used directly in HTTP requests (SSRF risk) | high |
| INPUT-010 | Regex with user input without escape | medium |

#### Auth & Access Control

| Rule ID | Description | Severity |
|---------|-------------|----------|
| AUTH-001 | API route with mutation (POST/PUT/DELETE) lacks auth check | critical |
| AUTH-002 | Supabase table referenced in code has no RLS policies defined | critical |
| AUTH-003 | JWT validated client-side only (no server verification) | critical |
| AUTH-004 | Route uses `params.id` in query without ownership check | high |
| AUTH-005 | `supabase.auth.admin` used outside server-only modules | critical |
| AUTH-006 | Middleware runs after route handler (execution order wrong) | high |
| AUTH-007 | Session/JWT secret shorter than 32 characters | high |
| AUTH-008 | JWT algorithm set to `none` or weak (`HS256` with short secret) | critical |
| AUTH-009 | Role check uses string comparison on user-controlled field | high |
| AUTH-010 | OAuth callback missing state parameter validation | high |

#### File Upload

| Rule ID | Description | Severity |
|---------|-------------|----------|
| UPLOAD-001 | Upload handler does not validate MIME type server-side | high |
| UPLOAD-002 | Upload handler does not enforce file size limit | medium |
| UPLOAD-003 | Uploaded files served from same domain as application (no subdomain isolation) | high |
| UPLOAD-004 | User-provided filename used directly in storage path (path traversal risk) | critical |
| UPLOAD-005 | Upload handler accepts `image/svg+xml` without sanitization (XSS vector) | high |
| UPLOAD-006 | No `Content-Disposition: attachment` header on downloadable uploads | medium |
| UPLOAD-007 | Client-side-only file validation (no server-side check) | high |
| UPLOAD-008 | Supabase storage bucket marked public without access control | high |
| UPLOAD-009 | Archive files (zip, tar) accepted without extraction safeguards | medium |

### Rule Execution

- All rules run in parallel (via `Promise.all`)
- Rules filter by `appliesTo` matching current stack profile
- Each rule receives a read-only reference to the ProjectModel
- Rules return `Finding[]` and are pure functions (no side effects)
- Time budget: under 5 seconds for all rules across a typical project

---

## Layer 3: AI Semantic Analysis (Phase 3, design only)

**Not in Phase 1 MVP. Specified here for completeness.**

Takes the ProjectModel + rule findings, sends targeted prompts to Claude for deeper analysis.

### Key Design Points

- **Scoped prompts only.** AI receives specific code sections with specific questions, never "find all vulnerabilities in this codebase"
- **No tool use by AI.** The AI receives context and returns analysis. It cannot execute commands, read files, or make requests
- **Output validation.** Findings parsed through Zod schemas, file paths validated against the recon model, hallucinated findings dropped
- **Nonce tagging.** Every AI prompt includes a per-request nonce, responses validated before findings accepted (prevents prompt injection from malicious code in scanned projects)
- **Cost control.** Token budget in `.sentinelrc.json`, file-hash-based caching, default to `claude-sonnet-4-6`

### Analysis Types

- Auth flow tracing (complete middleware chain analysis)
- Access control reasoning (IDOR/BOLA on endpoints with ownership implications)
- Data flow analysis (input-to-output tracing across file boundaries)
- Business logic review (state machines, payment flows, invitation systems)
- Finding enrichment (severity re-evaluation for rule findings)

---

## Layer 4: Active Probe (Phase 4, design only)

**Not in Phase 1 MVP. Specified here for completeness.**

Hits the running application. Confirms or refutes theoretical findings. Discovers runtime-only issues.

### Aggression Levels

| Check | Passive | Standard | Intrusive |
|-------|:-------:|:--------:|:---------:|
| HTTP header inspection | yes | yes | yes |
| CSP/CORS/security header audit | yes | yes | yes |
| SSL/TLS configuration check | yes | yes | yes |
| Response body scanning for secrets | yes | yes | yes |
| Endpoint mapping (follow links, parse JS) | yes | yes | yes |
| Rate limit testing | no | yes | yes |
| Auth endpoint probing | no | yes | yes |
| IDOR testing | no | yes | yes |
| JWT decode and claim analysis | no | yes | yes |
| File upload with benign test files | no | no | yes |
| XSS payload reflection testing | no | no | yes |
| Form submission with malicious input | no | no | yes |
| Test account creation with cleanup | no | no | yes |

### Authorization Enforcement

- First run against a target requires `--authorize` flag
- Authorization stored in `.sentinelrc.json` per target URL
- Intrusive level requires re-authorization every run (never cached)
- All probe requests include `X-Sentinel-Scan: true` header
- Full request/response log in `.sentinel/probe-log.jsonl`

### Safety Rails

- Rate self-limit: max 10 requests/second against target
- Request caps: 500 (passive), 2000 (standard), 5000 (intrusive)
- Cleanup obligation: every mutation tracked, cleaned up on completion or abort
- Kill switch: `Ctrl+C` stops all requests and runs cleanup

---

## CLI Interface

### Commands

```bash
sentinel scan <path>                    # Recon + Rules (Phase 1 MVP default)
sentinel scan <path> --ai               # Add AI semantic analysis (Phase 3)
sentinel probe <path> --target <url>    # Recon + Rules + Active probe (Phase 4)
sentinel audit <path> --target <url>    # All four layers (Phase 4)
sentinel report <path>                  # Regenerate report from cached findings
sentinel init                           # Create .sentinelrc.json in project
```

### Flags

```bash
# Aggression (probe only)
--level passive              # Headers, recon, response inspection only
--level standard             # + endpoint fuzzing, auth testing, rate limits
--level intrusive            # + test accounts, uploads, payload injection

# Authorization (probe only)
--authorize                  # Explicit permission to probe this target
--target <url>               # Running application URL

# Output
--format terminal            # Default, colored CLI
--format json                # JSON to stdout
--format html                # Self-contained HTML report
--format all                 # All three, written to .sentinel/reports/
--out <dir>                  # Custom output directory

# Filtering
--domains <list>             # Comma-separated domain names
--severity <level>           # Minimum severity to report (info/low/medium/high/critical)
--fail-on <level>            # Exit code 1 if findings at or above level

# AI (Phase 3)
--ai                         # Enable AI layer
--model <name>               # Override default Claude model
--max-tokens <n>             # Override token budget

# Other
--git-history                # Include git history scanning for secrets
--cache                      # Use cached results from previous scan
--verbose                    # Debug logging
```

### Exit Codes

- `0` - No findings at or above `--fail-on` threshold
- `1` - Findings at or above threshold
- `2` - Scan error (parse failure, missing dependency, etc.)
- `3` - Authorization error (probe without `--authorize`, etc.)

### Configuration File

`.sentinelrc.json` in project root:

```json
{
  "stack": "nextjs-supabase",
  "domains": ["all"],
  "exclude": ["node_modules", ".next", "dist", "out", "build"],
  "severity": {
    "failOn": "high"
  },
  "ai": {
    "enabled": false,
    "model": "claude-sonnet-4-6",
    "maxTokens": 50000
  },
  "probe": {
    "defaultLevel": "standard",
    "target": "http://localhost:3000",
    "authorizedTargets": []
  },
  "output": {
    "format": "terminal",
    "dir": ".sentinel/reports"
  }
}
```

---

## Output Formats

### Terminal

Color-coded, grouped by severity then domain. Shows finding ID, title, domain, location, layer source, and a brief remediation hint. Summary table at the end with domain/severity breakdown.

### JSON

Structured output including:
- Scan metadata (version, timestamp, project identity, layer status, duration)
- Summary counts (by severity, confidence, domain)
- Full `findings` array
- Full `ProjectModel` (for downstream tooling consumption)

Written to stdout by default or `.sentinel/reports/<date>-<project>.json` with `--format all`.

### HTML (Phase 2)

Self-contained single HTML file (no external dependencies, no CDN references). Features:
- Executive summary with severity donut, domain heatmap, confidence breakdown
- Sortable findings table (severity, domain, confidence, layer)
- Inline expandable finding details with code snippets and evidence
- Project map section visualizing discovered routes, endpoints, auth flows
- Comparison mode showing delta vs. previous scan

---

## Security Hardening

Sentinel analyzes potentially adversarial code. It must not be exploitable by the projects it scans.

### Filesystem Boundaries

Deny-list enforced in `src/utils/fs.ts`:

```typescript
const DENY_PATHS = [
  /\/proc\//, /\/sys\//, /\/dev\//,
  /\/etc\//, /\/root\//, /\.ssh\//,
  /\.env$/,   // Existence check only, never read contents
];
```

- Source code is read for AST analysis
- Lockfiles are parsed for dependency data
- `.env` files are checked for existence and gitignore status, never read
- Git history is only scanned with explicit `--git-history` flag

### No Execution

- No `eval()`, `require()`, `import()`, or `new Function()` on target code
- AST parsing via TypeScript compiler API (read-only mode) or tree-sitter
- Dependency analysis reads lockfiles, never runs `npm install` in target directory
- Probe layer uses its own HTTP client, never invokes target's server code

### AI Layer Isolation (Phase 3)

- AI prompts include per-request nonce, responses validated before findings accepted
- File paths in AI responses cross-checked against the recon model
- Zod schema validation on all AI output
- AI has no tool access, cannot read files or make network requests
- Scoped prompts only, never "analyze this whole codebase"

### Probe Authorization (Phase 4)

- Explicit `--authorize` flag for first run against any target
- Intrusive level requires re-authorization every run
- Rate limiting enforced at HTTP client level (not a prompt instruction)
- Request caps are hard limits, not suggestions
- All mutations tracked with cleanup obligations
- Append-only probe log for audit trail

---

## Directory Structure

```
sentinel/
├── src/
│   ├── cli.ts                      # Entry point: arg parsing, orchestration
│   ├── config.ts                   # .sentinelrc.json loading, validation
│   ├── model/
│   │   ├── types.ts                # ProjectModel, Finding, SecurityDomain
│   │   └── severity.ts             # Severity scoring, confidence calculation
│   ├── layers/
│   │   ├── recon/                  # Layer 1: discovery
│   │   ├── rules/                  # Layer 2: deterministic checks
│   │   ├── ai/                     # Layer 3: semantic analysis (Phase 3)
│   │   └── probe/                  # Layer 4: active testing (Phase 4)
│   ├── output/
│   │   ├── terminal.ts             # Colored CLI output
│   │   ├── json.ts                 # Structured JSON output
│   │   ├── html/                   # HTML report (Phase 2)
│   │   └── diff.ts                 # Scan comparison
│   └── utils/
│       ├── ast.ts                  # TypeScript AST helpers (read-only)
│       ├── fs.ts                   # Filesystem with deny-path enforcement
│       ├── git.ts                  # Git history scanning (opt-in)
│       └── logger.ts               # Structured logging
├── stacks/
│   └── nextjs-supabase/
│       ├── profile.ts              # Stack-specific recon hints
│       └── rules.ts                # Stack-specific rules
├── payloads/
│   ├── xss.json                    # Benign marker payloads (Phase 4)
│   ├── upload-files/               # Benign test files (Phase 4)
│   └── headers.json                # Expected security headers
├── package.json
├── tsconfig.json
└── .sentinelrc.defaults.json
```

---

## Build Phases

### Phase 1: MVP (spec complete, ready to implement)

- Full Recon layer for `nextjs-supabase` stack
- Rules layer with 4 domains: Secrets, Input, Auth, Upload
- Terminal + JSON output
- Basic config file support
- `sentinel scan` command

**Deliverable:** Working CLI that catches every pentest finding plus equivalent issues the pentester didn't have time to find.

### Phase 2: Completeness

- Remaining 6 rule domains: API Security, Crypto, Supply Chain, Infrastructure, Business Logic, Logging
- HTML report generator
- Comparison/diff mode
- CI integration examples

### Phase 3: Intelligence

- AI layer with all prompt types
- Token budget management and caching
- Stack-specific AI prompts (Supabase RLS, Next.js middleware)

### Phase 4: Active Testing

- Probe layer starting with passive level
- Authorization and cleanup systems
- Standard level checks
- Intrusive level checks (last)

### Phase 5: Ecosystem

- Additional stack profiles
- Plugin contract formalization
- Published to npm as `@franklabs/sentinel`

Each phase becomes its own brainstorm + spec cycle.

---

## Testing Strategy (Phase 1)

Sentinel needs its own test coverage to be trustworthy. It also needs representative vulnerable projects to test against.

### Unit Tests

- Each rule has its own test file with vulnerable and safe code samples
- Rule receives a hand-built `ProjectModel`, must return expected findings
- Recon discoverers tested against fixture projects in `tests/fixtures/`

### Integration Tests

- Full scan against a deliberately vulnerable fixture project
- Every Phase 1 rule must produce its finding exactly once on the fixture
- Fixture project mirrors `nextjs-supabase` structure with seeded vulnerabilities

### Snapshot Tests

- Terminal output and JSON output compared against committed snapshots
- Severity counts and finding IDs locked to prevent regressions

### Real-World Validation

- Scan at least three of Ty's actual projects before declaring Phase 1 done
- Compare findings against the pentest report on the tested project
- Any pentest finding not detected is a Phase 1 gap and must be fixed before ship

---

## Open Questions (to resolve before Phase 2)

- Should Phase 2 add `react-vite-supabase` as a second stack profile, or stay single-stack and add more rules?
- Should the HTML report be interactive (filtering, search) or static?
- How does `sentinel` integrate with the existing `/production-ready-audit` skill? Does the skill call `sentinel`, or are they independent?
- Where does the CI integration live? A separate repo? A GitHub Action?

These can be decided when Phase 2 starts; they do not block Phase 1.
