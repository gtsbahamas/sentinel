# Sentinel Probe Layer — Design Spec

*Date: 2026-04-12*
*Status: Design draft, awaiting review and implementation plan*
*Scope: Phase 4 probe layer for sentinel. Follows the AI layer spec (2026-04-11-ai-layer-design.md) and extends the top-level design (2026-04-10-sentinel-security-agent-design.md).*

---

## 1. Context & Motivation

Sentinel's `ProjectModel.layers` declares four layers: `recon`, `rules`, `ai`, `probe`. The first three are static analysis — they never touch the running application. The probe layer is the one that actually sends HTTP requests and observes responses. It is the only layer that can produce `confidence: "confirmed"` findings (per `AIFindingSchema`'s confidence cap invariant).

Static analysis infers what the code *probably* does. Probe verifies what the deployed app *actually* does. They answer different questions, and a report that combines both is qualitatively stronger than either alone — a rules finding tagged `probe-confirmed` is evidence, not speculation.

This spec defines the probe layer in full. Build order within Phase 4 keeps passive-level as the first deliverable (shipped in v0.2); standard and intrusive land in later minors. The layer ships gated behind explicit CLI commands (`sentinel probe`, `sentinel audit`) and an `--authorize` flag — no default scan path ever produces network traffic.

### Goals

- Add a fourth layer that confirms or refutes findings from rules/AI by observing runtime behavior
- Three aggression levels (passive, standard, intrusive) with hard safety budgets and explicit authorization
- Authorization model that makes accidental scans of the wrong target structurally impossible
- Cleanup registry that tracks every mutation and executes rollback before the command returns
- Append-only probe log for full audit trail
- Findings flow through the existing `Finding[]` pipeline with a new `probeEvidence` field; output formatters, diff command, and exit codes need no structural changes
- Mock HTTP client by default; live tests gated by `RUN_PROBE_LIVE_TESTS=1`

### Non-goals

- Fuzzing beyond the check catalog defined in §6 — probe is targeted, not a generic fuzzer
- Browser automation / headless Chrome — separate tool
- Load testing, DoS confirmation, or stress testing
- Credential brute force, password spray, or any form of authentication attack
- Stored XSS / persistence attacks (require multi-session replay, out of scope)
- SQL injection (blind/time-based) — too risky for probe's scale, too low-value per request
- Network-layer scans (port sweep, service fingerprinting) — use nmap
- Authenticated probe support in v0.2 (passive-only deliverable needs no credentials)

### Success criteria (v0.2 passive ship)

- `sentinel probe <path> --target <url> --authorize` runs end-to-end against a local dev server
- Passive-level run produces zero mutations — enforced by check catalog and lint rule
- Every probe request carries `X-Sentinel-Scan: <version>` header; every request/response logged to `.sentinel/probe-log.jsonl`
- At least one rules finding on the test fixture gets auto-confirmed (and at least one gets auto-refuted) by a passive check
- Cleanup registry infrastructure lands even though no passive check uses it — needed for standard/intrusive follow-up
- Authorization missing → exit code 3, never a silent pass
- Full unit + integration test suite passes with mock HTTP client; no network access in CI

---

## 2. Design Decisions

All decisions recorded here before any implementation file is written. Decisions marked (draft) need user review before lock-in.

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Entry point | New commands `sentinel probe` / `sentinel audit`. `sentinel scan` never runs probe. | Keeps scan a pure static-analysis path. Any network activity requires typing `probe` explicitly. No flag combinations can accidentally enable network calls. |
| 2 | Build order within Phase 4 | Infrastructure + passive checks for v0.2; standard in v0.3; intrusive in v0.4 | Passive is the smallest surface and needs zero authenticated-probe complexity. Infrastructure (auth state machine, HTTP client, cleanup registry, probe log) must land with v0.2 because standard/intrusive depend on it. |
| 3 | Target resolution | Probe trusts recon + rules + AI findings as target source. No independent endpoint discovery. | Duplicate discovery is waste and creates target drift. If recon missed an endpoint, the fix is in recon, not probe. |
| 4 | HTTP client | Single shared rate-limited client. Checks cannot make raw HTTP calls. Enforced by ESLint rule + code review. | Rate limits, header tagging, and logging must be unbypassable. A check that calls `fetch` directly breaks the safety model. |
| 5 | Authorization model | Per-target `--authorize` flag + persisted entry in `.sentinelrc.json`. Intrusive level NEVER cached — re-prompt every run. | First-run gate prevents accidental scans. Intrusive re-prompt prevents credential-like reuse of authorization. |
| 6 | Cleanup protocol | Obligations registered BEFORE mutation fires. LIFO execution. Blocking obligations gate exit code. | Registering after means a crash loses the record. LIFO because later mutations may depend on earlier ones. |
| 7 | Check interface | Each check is an async fn taking (target, client, registry, priorFindings). Static declaration of level + domain. | Mirrors rules layer's function-based check style. Static metadata allows filtering before execution. |
| 8 | Finding merge semantics | Probe findings are either "new" (runtime-only vulns) or "confirmations" (upgrade prior finding to `confirmed` in-place). Refutations drop the prior finding but are annotated in output. | Preserves diff command semantics — no row churn from probe confirming an existing row. |
| 9 | Mock HTTP client | Ships by default as test fixture. Real fetch attempts in test mode throw loudly. | Mirrors AI layer's `MockProvider` pattern. Keeps CI fast and free. |
| 10 | Probe log format | `.sentinel/probe-log-<runId>.jsonl`, append-only, redacted at write time. One file per run; last 10 retained. | Audit trail for security teams; rotation prevents unbounded growth. |
| 11 | Concurrency (draft) | Sequential for v0.2. Single check-at-a-time. Revisit once real run times are observed. | Keeps rate-limit math simple. Parallel probing could mask rate-limit bugs. |
| 12 | Target deny-list (draft) | Hardcoded deny-list of well-known public services (google.com, microsoft.com, amazon.com, etc.). RFC1918 requires `--internal-network` flag. Public TLDs require `--allow-public` flag AND cannot run intrusive without re-confirmation. | Typo protection. Someone typing `--target google.com` during testing shouldn't accidentally scan anything. |

### Rejected alternatives

- **Probe runs automatically under `sentinel scan`** — rejected. Mixing static and runtime behavior behind one command is a liability. If a user's CI pipeline runs `sentinel scan` and it accidentally starts hitting production, that's a firing offense. Explicit command separation is non-negotiable.
- **Probe does its own endpoint discovery via crawling** — rejected. Recon already builds the endpoint list. Probe re-crawling introduces target drift. If recon is incomplete, the answer is fixing recon, not layering a crawler on probe.
- **Checks make HTTP calls via raw fetch** — rejected. Rate limiting, header tagging, and logging must be enforced at one choke point. Checks that bypass the shared client break the safety model.
- **Cleanup obligations are best-effort by default** — rejected. Every mutation gets a named obligation and a severity. Blocking cleanup failures gate the exit code. Anything else gives attackers a failure mode where probe leaves test artifacts in the target.
- **Authorization never expires** — rejected. Default expiry 30 days; expired entries are REMOVED (not refreshed), so the user re-reads the scope before re-authorizing.
- **Probe findings are stored as new `Finding` rows** — rejected. Updating existing findings in-place with `probeEvidence` preserves diff-command semantics. New runtime-only findings still create rows.
- **Probe layer owns its own config file** — rejected. Config lives in `.sentinelrc.json` under `probe: {...}`, consistent with AI layer config location.

---

## 3. Architecture

### 3.1 File layout

```
src/layers/probe/
├── index.ts               runProbe(args) entry point
├── orchestrator.ts        level + check scheduling, cleanup coordination
├── authorization.ts       --authorize flow, sentinelrc persistence, expiry
├── http-client.ts         rate-limited client, header tagging, redaction
├── target-resolver.ts     ProjectModel + findings → ProbeTarget[]
├── cleanup-registry.ts    LIFO obligation tracker with signal handler
├── probe-log.ts           .sentinel/probe-log-<runId>.jsonl writer
├── merge.ts               merges ProbeFindings with existing findings
├── schema.ts              Zod schemas for ProbeFinding, ProbeEvidence
└── checks/
    ├── base.ts            ProbeCheck interface, shared helpers
    ├── passive/
    │   ├── security-headers.ts
    │   ├── tls-configuration.ts
    │   ├── endpoint-enumeration.ts
    │   ├── response-body-secrets.ts
    │   └── cors-configuration.ts
    ├── standard/          (v0.3+)
    │   ├── rate-limit-probe.ts
    │   ├── auth-endpoint-probe.ts
    │   ├── idor-probe.ts
    │   └── jwt-claim-audit.ts
    └── intrusive/         (v0.4+)
        ├── xss-reflection.ts
        ├── file-upload.ts
        └── form-fuzzing.ts

tests/layers/probe/
├── authorization.test.ts
├── http-client.test.ts
├── target-resolver.test.ts
├── cleanup-registry.test.ts
├── probe-log.test.ts
├── merge.test.ts
├── orchestrator.test.ts
└── checks/passive/
    ├── security-headers.test.ts
    ├── tls-configuration.test.ts
    ├── endpoint-enumeration.test.ts
    ├── response-body-secrets.test.ts
    └── cors-configuration.test.ts

tests/integration/
├── probe-passive.test.ts     end-to-end with MockHttpClient
├── probe-confirm.test.ts     probe upgrades prior finding to confirmed
├── probe-refute.test.ts      probe drops a refuted prior finding
├── probe-auth-deny.test.ts   missing authorization → exit 3
└── probe-cleanup.test.ts     obligation registered and executed

tests/fixtures/probe-scan/
├── project/                  tiny Next.js app with intentional flaws
└── server/                   tiny Express reflector for live tests
```

### 3.2 Pipeline position

```
sentinel scan  : runRecon → runRules → (optional) runAI                         → format output
sentinel probe : runRecon → runRules                        → runProbe          → format output
sentinel audit : runRecon → runRules → runAI → mergeFindings → runProbe         → format output
```

Probe sits after AI so it can consume AI findings as targets. `sentinel probe` skips AI (cost reasons); `sentinel audit` is the "everything" command. `sentinel scan` never runs probe.

### 3.3 Invariants enforced across the layer

1. **Authorization required**: every probe run requires a valid authorization entry for the target host. Missing = exit 3.
2. **Intrusive never cached**: intrusive authorization must be re-granted via interactive prompt every run. No flag bypasses this.
3. **Rate limit enforced in client**: the shared HTTP client enforces request-cap and requests-per-second. Checks cannot bypass.
4. **Header tagging**: every outgoing request carries `X-Sentinel-Scan: <version>`. Enforced at client construction.
5. **Every request logged**: appended to `probe-log-<runId>.jsonl` before the request returns to the caller.
6. **Cleanup before success**: any mutation registers a cleanup obligation. All blocking obligations must succeed before the run returns exit 0.
7. **Confidence upgrade is the only path to `confirmed`**: no static layer can set `confidence: "confirmed"`. Only merge.ts, and only after a probe check returns matching runtime evidence.
8. **No target code execution**: probe cannot `require()` / `import()` target code. Only HTTP requests.
9. **Mock mode forbids real fetch**: `MockHttpClient` throws loudly if global `fetch` is called from within a check.
10. **Deny-list is a hard gate**: deny-listed hosts refuse to run regardless of flags. Safety rail against typos.
11. **Probe is additive to static layers**: probe never deletes a rule/AI finding. Refutation annotates + demotes, never removes from history.

---

## 4. Type Contracts (Type-First)

All types are defined before any implementation file is written.

### 4.1 Additions to `src/model/types.ts`

```ts
export type AggressionLevel = "passive" | "standard" | "intrusive";

export interface ProbeConfig {
  enabled: boolean;               // only true when called from probe/audit command
  level: AggressionLevel;
  targetUrl: string | null;       // required when enabled
  requestCaps: {
    passive: number;              // default 500
    standard: number;             // default 2000
    intrusive: number;            // default 5000
  };
  requestsPerSecond: number;      // default 10
  timeoutMs: number;              // default 10_000
  allowPublicHosts: boolean;      // --allow-public
  allowInternalNetwork: boolean;  // --internal-network
  denyHosts: string[];            // hardcoded deny-list
  logDir: string;                 // default .sentinel/
}

export interface ProbeAuthorizationEntry {
  targetOrigin: string;           // "https://staging.app.com[:port]"; scheme IS part of key
  level: "passive" | "standard";  // "intrusive" is never persisted
  grantedAt: string;              // ISO
  expiresAt: string;              // ISO, default grantedAt + 30 days
  scopeNote: string;              // user-entered reason
}

export interface ProbeTarget {
  kind: "endpoint" | "static-resource" | "baseline";
  url: string;
  method?: Route["method"];
  auth?: "required" | "unauthenticated" | "unknown";
  fromLayer: Layer | "recon";
  fromFindingId?: string;         // populated if this target came from a specific finding
  inputs?: ProbeTargetInput[];
}

export interface ProbeTargetInput {
  name: string;
  in: "query" | "body" | "header" | "path";
  type: "string" | "number" | "boolean" | "uuid" | "unknown";
  exampleValue?: string | number | boolean;
}

export interface ProbeEvidence {
  requestId: string;              // nonce, ties to probe-log jsonl
  checkId: string;                // e.g., "security-headers"
  aggressionLevel: AggressionLevel;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;   // Authorization/Cookie redacted
    bodyPreview?: string;              // first 1KB, truncation marker appended
  };
  response: {
    status: number;
    headers: Record<string, string>;   // Set-Cookie redacted
    bodyPreview: string;               // first 1KB, secrets redacted
    timingMs: number;
  };
}

export interface ProbeFinding extends Omit<Finding, "evidence"> {
  evidence: Evidence[];              // static evidence carried from prior layers; usually empty
  probeEvidence: ProbeEvidence;      // always present on probe findings
  confirms?: string;                 // id of a prior Finding this confirms
  refutes?: string;                  // id of a prior Finding this refutes
}

export interface ProbeError {
  kind:
    | "target-unreachable"
    | "auth-expired"
    | "rate-limited-by-target"
    | "cleanup-failed"
    | "check-error"
    | "cap-exceeded";
  message: string;
  checkId?: string;
  targetUrl?: string;
}

export interface ProbeRunResult {
  findings: ProbeFinding[];          // new probe-origin findings
  confirmedFindingIds: string[];     // prior findings upgraded to confirmed
  refutedFindingIds: string[];       // prior findings demoted (still in report, annotated)
  usedRequests: number;
  requestCap: number;
  aggressionLevel: AggressionLevel;
  targetOrigin: string;
  authorizationHost: string;
  errors: ProbeError[];
  cleanupObligationsExecuted: number;
  cleanupObligationsFailed: number;
  cleanupFailures: Array<{ obligation: string; error: string }>;
  probeLogPath: string;
  durationMs: number;
}
```

### 4.2 Check interface (`src/layers/probe/checks/base.ts`)

```ts
export interface ProbeCheck {
  readonly id: string;                          // "security-headers"
  readonly level: AggressionLevel;
  readonly domain: SecurityDomain;
  readonly description: string;

  /**
   * Does this check apply to the given target?
   * MUST be cheap and synchronous — no HTTP, no filesystem.
   */
  appliesTo(target: ProbeTarget, model: ProjectModel): boolean;

  /**
   * Execute the check. Implementation MUST:
   *  - Use the passed client for every HTTP call
   *  - Register every mutation with the registry BEFORE performing it
   *  - Return findings/errors without throwing for expected conditions
   *    (target down, 5xx, timeout); those become ProbeError entries
   *  - Throw only for programmer errors (unreachable code, invariant break)
   */
  run(ctx: ProbeCheckContext): Promise<ProbeCheckResult>;
}

export interface ProbeCheckContext {
  target: ProbeTarget;
  model: ProjectModel;
  client: HttpClient;
  registry: CleanupRegistry;
  priorFindings: readonly Finding[];
  runId: string;
}

export interface ProbeCheckResult {
  findings: ProbeFinding[];
  confirmed: Array<{ findingId: string }>;
  refuted: Array<{ findingId: string }>;
  errors: ProbeError[];
}
```

### 4.3 HTTP client (`src/layers/probe/http-client.ts`)

```ts
export interface HttpClient {
  request(req: HttpRequest): Promise<HttpResponse>;
  requestsUsed(): number;
  requestCap(): number;
}

export interface HttpRequest {
  method: "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "DELETE" | "PATCH";
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  intent: "read" | "mutate";        // mutate triggers extra budget accounting
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  timingMs: number;
  requestId: string;                 // same nonce as in probe-log entry
}

// Error classes (thrown by request()):
// - TargetUnreachable: DNS/connect failure, aborted request
// - RequestCapExceeded: per-level cap hit
// - RateLimitWaitExceeded: token bucket wait > 5s (only under pathological load)
// - TargetRateLimited: target returned 429 / 503 / Retry-After after backoff exhausted
```

### 4.4 Cleanup registry (`src/layers/probe/cleanup-registry.ts`)

```ts
export interface CleanupRegistry {
  register(obligation: CleanupObligation): string;   // returns obligation id
  executeAll(): Promise<CleanupResult>;
  pendingCount(): number;
}

export interface CleanupObligation {
  description: string;                    // "delete test file at /uploads/<id>"
  severity: "blocking" | "best-effort";
  timeoutMs?: number;                     // default 30_000
  cleanup: (signal: AbortSignal) => Promise<void>;
}

export interface CleanupResult {
  executed: number;
  failed: number;
  failures: Array<{
    obligationId: string;
    description: string;
    error: string;
    severity: "blocking" | "best-effort";
  }>;
}
```

### 4.5 Authorization store (`src/layers/probe/authorization.ts`)

```ts
export interface AuthorizationResolution {
  state: "granted" | "needs-prompt" | "denied" | "expired";
  entry?: ProbeAuthorizationEntry;
  reason?: string;
}

export function resolveAuthorization(args: {
  targetUrl: string;
  requestedLevel: AggressionLevel;
  config: ProbeConfig;
  existingEntries: ProbeAuthorizationEntry[];
  authorizeFlagPresent: boolean;
}): AuthorizationResolution;

export function promptForAuthorization(args: {
  targetUrl: string;
  requestedLevel: AggressionLevel;
  tty: NodeJS.ReadStream;
}): Promise<ProbeAuthorizationEntry | null>;

export function persistAuthorization(
  projectPath: string,
  entry: ProbeAuthorizationEntry,
): Promise<void>;
```

---

## 5. Authorization State Machine

### 5.1 States and transitions

| State | Meaning |
|-------|---------|
| `unauthorized` | No entry exists for this target + level |
| `granted-valid` | Entry exists, level matches or exceeds requested, not expired |
| `granted-expired` | Entry exists but `expiresAt` is in the past |
| `granted-lower-level` | Entry exists but for a lower level than requested (e.g., passive granted, standard requested) |
| `deny-listed` | Target host matches deny-list; cannot run regardless |
| `intrusive-session` | Transient in-memory state; always re-prompted, never persisted |

### 5.2 First-run flow

1. User runs `sentinel probe <path> --target <url>`
2. `resolveAuthorization` parses target URL, extracts `scheme://host[:port]`
3. Checks deny-list first. If matched → exit 3 with error naming the host.
4. Checks `allowPublicHosts` / `allowInternalNetwork` flags vs. target category.
5. Loads `.sentinelrc.json` `probe.authorizations[]`, searches for matching `targetOrigin`.
6. If no match AND `--authorize` absent → exit 3 with instruction on how to authorize.
7. If no match AND `--authorize` present → call `promptForAuthorization`, confirm target URL, confirm level, take a one-line scope note, persist to config (unless level is intrusive). Continue.
8. If match exists, check `expiresAt`. Expired → REMOVE the entry (forces user to consciously re-read scope), treat as no-match, go to step 6.
9. If match exists and level is lower than requested → behave as no-match for the higher level.

### 5.3 Intrusive re-prompt rule

Intrusive level:
- Never persisted to `.sentinelrc.json`
- Always triggers an interactive prompt with bold warning text
- Requires explicit `--level intrusive` on the CLI (no way to promote from passive/standard via config)
- Prompt must read from `/dev/tty` directly — piping `yes` through stdin cannot bypass it
- On non-TTY sessions (CI), intrusive probe is unsupported and exits 3

### 5.4 Target identity (scheme in key)

Authorization is keyed on `scheme://host[:port]`. Rationale:
- `http://staging.app.com` and `https://staging.app.com` are different targets from a TLS-check perspective
- A user who authorized HTTPS shouldn't be silently downgraded if someone flipped the URL
- Trivial to re-authorize both at once if needed

### 5.5 Deny-list (draft, user review)

Hardcoded deny-list of well-known public services:
```ts
const DEFAULT_DENY_HOSTS = [
  "google.com", "www.google.com", "google.co.*",
  "microsoft.com", "www.microsoft.com",
  "amazon.com", "www.amazon.com", "aws.amazon.com",
  "apple.com", "icloud.com",
  "github.com", "gitlab.com",
  "cloudflare.com",
  "facebook.com", "meta.com",
  "openai.com", "anthropic.com",
];
```

Typo protection: someone targeting `google.com` by accident never gets past resolveAuthorization. Users can't override via config (it's a hardcoded list, reviewed per release).

RFC1918 networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) require `--internal-network` flag. Loopback (127.0.0.0/8, ::1) requires no flag. Public IPs (anything else) require `--allow-public`.

---

## 6. Check Catalog

Each check has: id, level, domain, description, safety cost. Passive is the v0.2 deliverable; standard and intrusive are specified for completeness and will ship in later minors.

### 6.1 Passive level (v0.2)

| # | Id | Domain | What it does | Evidence produced | Mutations |
|---|----|--------|--------------|-------------------|-----------|
| P1 | `security-headers` | `infrastructure` | GET baseline URL and each endpoint. Inspect response for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Confirms or refutes rule findings about missing/weak headers. | Full response headers | None |
| P2 | `tls-configuration` | `cryptography` | Inspect TLS handshake (protocol version, cert chain, cipher suite) via Node tls module. Confirms rule findings about weak TLS. | Cert metadata, negotiated protocol/cipher | None |
| P3 | `endpoint-enumeration` | `auth-access-control` | For every `ApiEndpoint` in the model, issue a GET (or HEAD for mutation endpoints). Record status and select response headers. If rule findings say an endpoint requires auth and probe gets 200 without credentials, the finding is confirmed. | Per-endpoint status map | None (read-only verbs) |
| P4 | `response-body-secrets` | `secrets-exposure` | Re-run the secrets-layer regex rules against response bodies (first 1KB each). Catches API keys accidentally serialized in debug pages or error responses. | Matched secret patterns (redacted) | None |
| P5 | `cors-configuration` | `api-security` | Send OPTIONS preflight with benign but distinct Origin header. Inspect Access-Control-Allow-Origin/Methods/Credentials. Confirms or refutes rule findings about CORS misconfiguration. | Response headers | None |

All passive checks are explicitly read-only. The check base class has a sanity check: `if level === "passive" and req.intent !== "read"` → throw at runtime. Belt and suspenders with the lint rule.

### 6.2 Standard level (v0.3, specified)

| # | Id | Domain | What it does | Evidence | Safety |
|---|----|--------|--------------|----------|--------|
| S1 | `rate-limit-probe` | `api-security` | Send up to 20 GET requests in quick succession to an endpoint flagged as missing rate limits. Observe 429 rate and `Retry-After` headers. | Response sequence + timings | Read-only; respects target 429 |
| S2 | `auth-endpoint-probe` | `auth-access-control` | POST malformed payloads to known auth endpoints. Observe verbose errors, timing differences, user enumeration. Never attempts valid credentials. | Status + body previews | Read-only (failed auth = no state change) |
| S3 | `idor-probe` | `auth-access-control` | For endpoints with `:id` UUID params, GET with Nil UUID (`00000000-...`) and Max UUID (`ffffffff-...`) where a real ID belongs. Confirms IDOR findings by returning 200 for unauth holders. | Status + body diff | Read-only |
| S4 | `jwt-claim-audit` | `cryptography` | When any response sets a JWT cookie or returns one in body, decode header + claims. Flag `alg: none`, weak HMAC, missing `exp`, sensitive claims in plaintext. | Decoded header + claims (redacted) | Read-only |

### 6.3 Intrusive level (v0.4, specified)

| # | Id | Domain | What it does | Evidence | Cleanup |
|---|----|--------|--------------|----------|---------|
| I1 | `xss-reflection` | `input-injection` | Inject benign marker strings (e.g., `<sentinel-marker-${nonce}/>`) into form/query/header inputs. Check for unescaped reflection. Markers contain no executable content — detection is literal substring match. | Request body + reflection offsets in response | None (read-only input, no stored state) |
| I2 | `file-upload` | `file-upload` | Upload benign test files (1-byte `.txt`, valid 100x100 PNG) to discovered upload endpoints. Catches missing MIME validation, accepted-but-unparseable-by-backend cases, path traversal via filename. | Upload response + storage URL if returned | Blocking: delete uploaded file via DELETE endpoint if recon found one; manual cleanup instructions in error report otherwise |
| I3 | `form-fuzzing` | `business-logic` | Send POST with malformed bodies: truncated JSON, 10KB unicode strings, type mismatches, missing required fields. Observe error reflection, 500 responses, server-side stack traces leaked. | Body preview + stack trace excerpt | None (reads only, backend may log noise) |

**Explicitly out of scope at every level**: SQL injection (blind/time-based), NoSQL injection, OS command injection, LDAP injection, XXE, SSRF confirmation, RCE probing, path traversal beyond file uploads, prototype pollution. These are high-value checks but require payload libraries, target-fingerprint-aware shaping, and cleanup models we won't get right on first pass. They're a post-v0.4 concern.

---

## 7. HTTP Client & Safety Rails

### 7.1 Rate limiter (token bucket)

- Bucket capacity: 10 tokens (matches `requestsPerSecond` default)
- Refill rate: 10 tokens/sec, smooth
- Each `request()` consumes 1 token; blocks (doesn't spin) if bucket empty
- Max wait per call: 5 seconds; exceeded → throws `RateLimitWaitExceeded`
- Mutation requests (`intent: "mutate"`) consume 2 tokens — gives extra breathing room for intrusive checks

### 7.2 Request cap

- Per-level hard cap: passive 500, standard 2000, intrusive 5000
- Decrementing counter in client construction; not exposed to checks
- On cap exhaustion: request() throws `RequestCapExceeded`
- Orchestrator catches, reports `cap-exceeded` ProbeError, runs cleanup, exits gracefully

### 7.3 Per-request timeout

- Default 10s; overridable on HttpRequest
- Uses AbortController; no silent retries
- Exceeded = `TargetUnreachable` with `aborted: true`

### 7.4 Headers every request carries

```
X-Sentinel-Scan: 0.2.0
User-Agent: sentinel/0.2.0 (+https://github.com/franklabs/sentinel)
X-Request-Id: <nonce>
Accept-Encoding: identity
```

### 7.5 Headers explicitly never added by the client

- `Authorization`, `Cookie`, `X-API-Key`, `X-Auth-Token`, any `Set-Cookie` (probe doesn't carry state across requests; session-based testing is an authenticated-probe v0.4+ feature)

### 7.6 Redaction policy (applied at probe-log write time)

- Request headers matching `/auth|token|secret|key|password/i` → `[REDACTED]`
- Request body with Content-Type `application/x-www-form-urlencoded`: fields matching `/password|secret|token|api_?key/i` → `[REDACTED]`
- Response headers: `Set-Cookie` → `[REDACTED]` (still counted/logged, just not the value)
- Response body: first 1KB scanned by secrets rules; any match replaced with `[REDACTED_SECRET:<pattern-id>]`

### 7.7 Target-returned rate limiting

If target responds 429 or 503 with `Retry-After`:
1. First occurrence: backoff for min(Retry-After, 10s), retry ONCE
2. Second occurrence on same endpoint: mark endpoint as rate-limiting-active, skip further requests to it, continue other checks
3. 429s across 3+ endpoints: abort run with `rate-limited-by-target` ProbeError; assume the target is actively defending and we should stop

---

## 8. Cleanup Protocol

### 8.1 Obligation registration

```ts
// Inside a check:
const uploadId = generateNonce();
const obligationId = registry.register({
  description: `delete uploaded file /uploads/${uploadId}.png`,
  severity: "blocking",
  cleanup: async (signal) => {
    await client.request({
      method: "DELETE",
      url: `${target.url}/uploads/${uploadId}.png`,
      intent: "mutate",
      timeoutMs: 10_000,
    });
  },
});

// NOW perform the mutation
await client.request({
  method: "POST",
  url: uploadEndpoint,
  body: buildMultipart(uploadId),
  intent: "mutate",
});
```

Registering BEFORE the mutation is the key invariant. A crash between `register` and the mutation means the cleanup callback runs pointlessly (DELETE on a file that was never uploaded) — harmless. A crash AFTER the mutation but WITHOUT registration means the artifact is orphaned — bad.

### 8.2 Execution semantics

- **Order**: strict LIFO. Later mutations may depend on earlier ones.
- **Triggers**: normal run completion, SIGINT, SIGTERM, unhandled top-level exception, auth-expired mid-run
- **Per-obligation timeout**: 30 seconds default, overridable
- **Blocking vs best-effort**: any blocking failure → exit 2 with manual cleanup instructions; best-effort failure → logged and run continues

### 8.3 Signal handling

```ts
// In orchestrator.ts
process.on("SIGINT", async () => {
  logger.warn("SIGINT received, running cleanup obligations...");
  const result = await registry.executeAll();
  writeCleanupReport(result);
  process.exit(result.failed > 0 ? 2 : 130);
});
```

30-second grace period before force-exit. User sees cleanup progress on stderr.

### 8.4 v0.2 scope

Passive-only v0.2 ships the registry infrastructure even though no passive check uses it. Reasons:
- Standard/intrusive depend on it
- Signal handling and registry plumbing have to be exercised end-to-end
- A noop registry in v0.2 lets integration tests cover the "zero mutations, zero cleanups" path

---

## 9. CLI & Config Integration

### 9.1 Commands

```bash
sentinel probe <path> --target <url> --authorize       # runs recon + rules + probe
sentinel audit <path> --target <url> --authorize       # runs recon + rules + ai + probe
sentinel scan <path>                                    # never runs probe (unchanged)
```

`probe` does NOT run AI (cost reasons). `audit` is the "every layer" command.

### 9.2 Probe-specific flags

```
--target <url>              (required) running application URL, scheme://host[:port]
--level passive|standard|intrusive
                            default passive
--authorize                 grants authorization for this target; prompts interactively
--allow-public              allow public TLD targets
--internal-network          allow RFC1918 targets
--request-cap <n>           override default cap (still capped by level maximum)
--target-timeout <ms>       per-request timeout override
--probe-log-dir <path>      override .sentinel/ log location
```

`--level`, `--authorize`, and `--target` are only valid on `probe` and `audit`. Passing them to `scan` is a hard error.

### 9.3 `.sentinelrc.json` additions

```json
{
  "probe": {
    "defaultLevel": "passive",
    "requestsPerSecond": 10,
    "requestCaps": { "passive": 500, "standard": 2000, "intrusive": 5000 },
    "timeoutMs": 10000,
    "authorizations": [
      {
        "targetOrigin": "http://localhost:3000",
        "level": "passive",
        "grantedAt": "2026-04-12T14:00:00Z",
        "expiresAt": "2026-05-12T14:00:00Z",
        "scopeNote": "local dev server"
      }
    ]
  }
}
```

### 9.4 Output format additions (`src/output/json.ts`)

```jsonc
{
  "layers": {
    "recon": { "status": "complete", "duration_ms": 245 },
    "rules": { "status": "complete", "duration_ms": 1203 },
    "ai":    { "status": "complete", "duration_ms": 8744 },
    "probe": {
      "status": "complete",
      "duration_ms": 12034,
      "aggression_level": "passive",
      "target_origin": "https://staging.app.com",
      "authorization_host": "staging.app.com",
      "requests_used": 217,
      "request_cap": 500,
      "confirmations": 4,
      "refutations": 1,
      "errors": [],
      "cleanup_obligations_executed": 0,
      "cleanup_obligations_failed": 0,
      "probe_log_path": ".sentinel/probe-log-2026-04-12-140332.jsonl"
    }
  },
  "findings": [
    {
      "id": "AUTH-003",
      "layer": "rules",
      "confidence": "confirmed",
      "probeEvidence": { /* ProbeEvidence object */ }
    }
  ]
}
```

### 9.5 `diff` command interaction

Probe confirmations do not create new finding rows — they set `confidence: "confirmed"` and attach `probeEvidence` to existing findings. `diff` compares confidence transitions and emits "upgraded to confirmed" events distinct from "new finding" events.

Refutations: the prior finding is NOT removed. It remains in the report with `confidence: "refuted"` (new confidence value added to the enum) and a `refutation` field explaining the evidence. This preserves history through diff comparisons.

**Open: confidence enum needs a `"refuted"` value.** This affects `src/model/types.ts` and every output formatter. Decision needed before implementation.

### 9.6 Exit codes (unchanged from main spec)

- `0` — no findings at or above fail-on threshold, no probe errors, all cleanups succeeded
- `1` — findings at or above threshold
- `2` — scan error, cleanup blocking failure, cap exceeded mid-run
- `3` — authorization error (missing, expired, deny-listed)

---

## 10. Testing Strategy

### 10.1 Mock HTTP client

```ts
// Used by every unit and integration test
const client = new MockHttpClient({
  routes: [
    { match: { method: "GET", url: /\/api\/health/ }, response: { status: 200, body: "OK" } },
    { match: { method: "GET", url: /\/api\/users/ }, response: { status: 401, body: "Unauthorized" } },
  ],
  defaultResponse: { status: 404, body: "" },
});
```

- Records every request for assertions
- Default response is 404 (explicit configuration forced)
- Enforces rate limiter semantics
- Throws if real `globalThis.fetch` is spied-called during a test

### 10.2 Unit test coverage

| File | Coverage |
|------|----------|
| `authorization.test.ts` | State machine transitions, expiry, deny-list, scheme key, intrusive re-prompt refusal on non-TTY |
| `http-client.test.ts` | Rate limiting (token bucket math), cap enforcement, header injection, redaction at log write, target-returned 429 backoff |
| `target-resolver.test.ts` | Finding → target mapping for each domain, dedup when multiple findings point at same endpoint |
| `cleanup-registry.test.ts` | LIFO order, blocking vs best-effort, signal path, timeout per obligation |
| `probe-log.test.ts` | JSONL append, rotation, redaction consistency |
| `merge.test.ts` | Confirmation upgrades confidence in-place, refutation demotes but preserves, diff-compatible shape |
| `orchestrator.test.ts` | End-to-end orchestration with mock client: auth check → target resolution → check scheduling → finding merge → cleanup |
| `checks/passive/*.test.ts` | One per passive check, mock responses covering confirm/refute/no-signal |

### 10.3 Integration tests

- `probe-passive.test.ts` — orchestrator + real passive checks against mock client, fixture project
- `probe-confirm.test.ts` — seeded rules finding + matching probe evidence → confidence upgraded
- `probe-refute.test.ts` — seeded rules finding + contradictory probe evidence → finding demoted
- `probe-auth-deny.test.ts` — no authorization entry → exit 3
- `probe-deny-list.test.ts` — target matching deny-list → exit 3 regardless of flags
- `probe-cap.test.ts` — cap exceeded mid-run → graceful abort, cleanup runs, exit 2

### 10.4 Live tests (gated by `RUN_PROBE_LIVE_TESTS=1`)

Tiny Express server in `tests/fixtures/probe-scan/server/`:
- Routes that echo headers back
- Routes with intentional misconfigurations (missing CSP, permissive CORS, reflected query)
- Routes that return 429 after N requests (target rate limit testing)

Spin up on random port, run passive level against it, assert findings shape and log contents.

### 10.5 What is NOT tested in CI

- Real TLS handshake testing — requires valid cert; live tests only, manual QA
- Actual SIGINT handling — signal propagation tests are flaky across platforms; exercised via dedicated test script outside `vitest`
- Real rate limiting from production targets — never in CI

---

## 11. Open Questions

| # | Question | Current lean | Why it's open |
|---|----------|--------------|---------------|
| 1 | How does probe acquire credentials for authenticated checks? | Defer to v0.4 — passive-only v0.2 needs no auth | Decision affects check catalog for standard+ |
| 2 | Add `"refuted"` value to `Confidence` type? | Yes — needed for refutation semantics | Ripples through output formatters and diff |
| 3 | Concurrent check execution vs sequential | Sequential for v0.2 | Parallel could mask rate-limit bugs; revisit with real timing data |
| 4 | Probe log retention policy | Keep last 10 runs | May need per-run tagging for multi-target projects |
| 5 | Cleanup on Node segfault | Defer; no resume-cleanup command in v0.2 | Needs persisted obligation journal, extra complexity; revisit after first real crash |
| 6 | 404 as refutation | 404 is NOT refutation (could be undeployed endpoint) | Explicit contrary evidence (different status/body than rule expects) required for refutation |
| 7 | Deny-list governance | Hardcoded, reviewed per release | User override would defeat the purpose; is there a legitimate case? |
| 8 | Probe against non-HTTP targets | Out of scope for v0.2–v0.4 | gRPC, GraphQL, WebSocket probing needs different check shapes |
| 9 | Integration with AI layer's Stage A risk summary | None — probe reads findings, not risk summaries | Could prioritize probe targets by AI-declared risk; v0.3 enhancement |
| 10 | Probe runtime for large projects | Sequential at 10 req/sec with 500 cap = ~50 seconds for passive. Acceptable? | Parallelism would cut this; risk masked rate limits |

---

## 12. Out of Scope (Explicitly Deferred)

- Browser automation / headless Chrome / JavaScript execution on target pages
- Load testing, DoS confirmation, stress testing
- SQL injection, NoSQL injection, OS command injection, LDAP injection, XXE, SSRF confirmation, RCE probing
- Credential stuffing, password spray, account enumeration beyond passive signals
- Network-layer scanning (port sweep, service fingerprinting) — use nmap
- Stored XSS / persistence attack confirmation (requires multi-session replay)
- gRPC, GraphQL, WebSocket endpoints
- Authenticated probe workflow (v0.4+)
- Sentinel-orchestrated deployment of a test harness into the target environment
- Any check that writes data the target cannot clean up on its own

---

## 13. Success Criteria (v0.2 closing restatement)

- `sentinel probe tests/fixtures/probe-scan/project --target http://localhost:<port> --authorize` completes successfully against the live test server
- Passive level produces zero mutations, verified by mock client assertions across the full unit + integration test suite
- At least one seeded rules finding gets upgraded to `confirmed` via the `security-headers` or `cors-configuration` check
- At least one seeded rules finding gets marked `refuted` via `endpoint-enumeration` against an endpoint that correctly returns 401
- Missing authorization → exit 3, no network traffic, clear user instruction
- Deny-listed target → exit 3, no network traffic, clear user instruction
- `.sentinel/probe-log-<runId>.jsonl` exists with one line per request, redactions applied
- Full test suite passes without `RUN_PROBE_LIVE_TESTS=1`; live smoke test passes when enabled
- Typecheck clean, lint rule enforces "no raw fetch in probe checks"

---

## 14. Build Order (within v0.2)

1. Type contracts + schema (no implementation logic)
2. `http-client.ts` with rate limiter + cap + redaction + logging — alone, full tests
3. `cleanup-registry.ts` with signal handler — alone, full tests
4. `probe-log.ts` jsonl writer + rotation — alone, full tests
5. `authorization.ts` state machine + persistence — alone, full tests
6. `target-resolver.ts` — alone, full tests
7. `checks/base.ts` + `checks/passive/security-headers.ts` (simplest) — integration with HTTP client
8. Remaining passive checks one at a time
9. `merge.ts` confirmation + refutation logic
10. `orchestrator.ts` end-to-end
11. CLI wiring in `cli.ts` and `commands/probe.ts`
12. JSON output formatter updates
13. Integration tests
14. Live smoke test fixture and gated test

Each step shipped as a standalone bite with diff review before commit. No "wire it all at once" step.
