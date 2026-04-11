# Sentinel AI Layer — Design Spec

*Date: 2026-04-11*
*Status: Design approved, awaiting implementation plan*
*Scope: AI layer for sentinel scanner. Probe layer is a separate follow-up cycle.*

---

## 1. Context & Motivation

Sentinel's `ProjectModel.layers` declares four layers: `recon`, `rules`, `ai`, `probe`. Today only `recon` and `rules` are implemented. The AI layer is sentinel's primary differentiator vs gitleaks/semgrep: semantic analysis that catches business-logic vulnerabilities (IDOR, authorization bypass, unsafe flow composition) which pattern-matching rules structurally cannot catch.

This spec defines the AI layer. The Probe layer — runtime/dynamic confirmation — is deliberately excluded and will get its own spec after the AI layer ships.

### Goals

- Add a pluggable AI analysis layer behind an opt-in `--ai` flag
- Support Anthropic and OpenAI from day one via a provider abstraction
- Produce findings that flow through the existing `Finding[]` pipeline — zero changes to output formatters, diff command, or exit-code logic
- Safe by default: hard cost caps, graceful degradation, never crashes a scan
- Testable without burning API tokens (mock-first, live-gated)

### Non-goals

- Runtime probing or dynamic testing (Probe layer, separate spec)
- Agent-style file retrieval tools (v0.4+ upgrade path)
- Multi-stage pipelines with validation/dedup stages (rejected due to compounding-hallucination risk)
- Cross-provider finding parity — Anthropic and OpenAI will find different things; that's expected

### Success criteria

- `sentinel scan --ai --ai-provider mock` runs end-to-end on the existing test fixture without real API calls
- `sentinel scan --ai --ai-dry-run` prints a token/cost estimate without any provider calls and without requiring an API key
- Running against `tests/fixtures/ai-scan/` with the real Anthropic provider produces at least one finding and stays under $0.25
- Full test suite (81 existing + new AI tests) passes without any live network calls
- AI findings appear in terminal/JSON/HTML output tagged `layer: "ai"` with zero changes to output formatters

---

## 2. Design Decisions

All decisions were locked during brainstorming before any design was presented. Each is recorded here with its rationale.

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | Scope | AI layer first; Probe layer follows in its own cycle | Probe needs runtime context (auth, dev server, fixtures). AI layer is pure I/O and ships faster. AI output can feed Probe later. |
| 2 | Trigger | Opt-in `--ai` flag; config override via `.sentinelrc.json` | Fast/cheap default; power-user escalation. Zero cost when disabled. |
| 3 | Provider strategy | Pluggable `AIProvider` interface; Anthropic + OpenAI from day one | User preference for flexibility over YAGNI. Interface stays small. |
| 4 | Context strategy | Per-endpoint analysis over `model.endpoints[]` | Natural unit for business-logic vulns. Parallelizes. Prompt-cache friendly. |
| 5 | Output contract | Structured output (forced tool-use on Anthropic, `json_schema strict` on OpenAI) + Zod validation on receive | Strongest typing guarantees; kills parse-failure classes. Zod as belt-and-suspenders. |
| 6 | Cost controls | Hard budget cap + per-endpoint token cap + `--ai-dry-run` + prompt caching + final cost report | Safe-by-default defaults ($2 cap). Dry-run builds user confidence. |
| 7 | Pipeline shape | Approach 1 (thin orchestrator) + optional `--ai-deep` Stage A for project-wide risk summary | Avoids compounding hallucination of a full 3-stage pipeline. Stage A is advisory-only: it biases priority order, does not frame what Stage B finds. |
| 8 | Testing | Mock provider by default (always on) + gated live tests (`RUN_AI_LIVE_TESTS=1`) | Mocks cover wiring; live tests cover drift. CI stays fast/free. |

### Rejected alternatives

- **Anthropic-only provider** — rejected in favor of pluggable from day one (decision 3)
- **Agent-style retrieval (approach 2)** — rejected: expensive tool-use loops, hard to mock, unpredictable cost, file-access sandbox complexity
- **Full multi-stage pipeline (approach 3)** — rejected: 3x cost/latency, compounding hallucination risk in Stage B primed by Stage A, harder to debug
- **JSON-mode + regex parsing (output B)** — rejected in favor of structured output (decision 5)
- **Recorded-fixture playback testing** — rejected: fixture drift produces misleading results as models evolve

---

## 3. Architecture

### 3.1 File layout

```
src/layers/ai/
├── index.ts              runAI(model, config) — entry point
├── orchestrator.ts       endpoint loop, concurrency, Stage A coordination
├── stage-a.ts            optional project-wide risk summary pass
├── providers/
│   ├── base.ts           AIProvider interface + shared types
│   ├── anthropic.ts      forced tool-use, prompt caching, pricing constants
│   ├── openai.ts         response_format json_schema strict, pricing constants
│   └── mock.ts           deterministic test provider
├── prompts.ts            project summary builder, prompt templates
├── context-builder.ts    per-endpoint context assembly
├── schema.ts             Zod schemas + shared tool definition
├── budget.ts             BudgetTracker, cost math, cap enforcement
└── dry-run.ts            pre-run cost estimation

tests/layers/ai/
├── orchestrator.test.ts
├── providers/
│   ├── anthropic.test.ts
│   ├── openai.test.ts
│   └── mock.test.ts
├── context-builder.test.ts
├── schema.test.ts
├── budget.test.ts
├── dry-run.test.ts
└── live/
    └── smoke.test.ts     gated by RUN_AI_LIVE_TESTS=1

tests/fixtures/ai-scan/   tiny Next.js + Supabase fixture project
tests/integration/
├── ai-scan.test.ts       end-to-end with mock provider
└── ai-diff.test.ts       AI findings flow through diff command
```

### 3.2 Pipeline position

```
runRecon → runRules → (if options.ai) runAI → merge findings → format output
```

`runAI` sits between `runRules` and output formatting. It is:

- **Additive**: never removes rule findings
- **Pure**: never mutates `model` (returns new findings)
- **Graceful**: catastrophic failures leave the user with the same scan they'd have had without `--ai`, plus a warning
- **Skippable**: no-op when `options.ai !== true`, zero cost when disabled
- **exitAfterDrain-safe**: no `process.exit()` calls (per existing CLI convention)

### 3.3 Invariants enforced across the layer

1. **Confidence cap**: AI findings max out at `confidence: "high"`. Only runtime probe evidence produces `"confirmed"`. Enforced in `AIFindingSchema` Zod enum.
2. **Layer tagging**: every finding produced by this layer has `layer: "ai"`.
3. **ID prefix**: every AI-produced `ruleId` matches `/^AI-[A-Z]+-\d{3}$/`. Enforced in schema.
4. **No network in mock mode**: `MockProvider` must fail loudly if real `fetch` is called.
5. **No cost accounting in mock mode**: mock pricing is zero, so tests cannot accidentally simulate real budget exhaustion.
6. **Pre-flight budget check**: orchestrator checks `budget.wouldExceed()` before every provider call, never after.

---

## 4. Type Contracts (Type-First)

All types are defined before any implementation file is written. Invalid states must be unrepresentable.

### 4.1 Additions to `src/model/types.ts`

```ts
// Layer union already contains "ai" — no change needed.

export interface AIConfig {
  enabled: boolean;                    // from --ai flag or .sentinelrc
  provider: "anthropic" | "openai" | "mock";
  model: string;                       // e.g., "claude-sonnet-4-6", "gpt-5"
  deep: boolean;                       // --ai-deep → run Stage A
  maxCostUsd: number;                  // hard budget cap, default 2.0
  maxTokensPerEndpoint: number;        // per-call input cap, default 8000
  concurrency: number;                 // parallel endpoint analyses, default 3
  dryRun: boolean;                     // estimate only, don't call API
}

export interface AIUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;             // Anthropic prompt-cache hits
  cacheWriteTokens: number;
  estimatedCostUsd: number;
}

export interface AIRunResult {
  findings: Finding[];                 // tagged layer: "ai"
  usage: AIUsage;
  stageA: StageARiskSummary | null;    // present iff deep mode
  errors: AIError[];                   // non-fatal issues per endpoint
  budgetExhausted: boolean;
  endpointsAnalyzed: number;
  endpointsSkipped: number;
  durationMs: number;
}

export interface StageARiskSummary {
  projectRisks: Array<{
    domain: SecurityDomain;
    description: string;
    affectedEndpoints: string[];       // subset of model.endpoints[].path
    severity: Severity;
  }>;
  priorityOrder: string[];             // endpoint paths, most-risky-first
}

export interface AIError {
  kind: "provider" | "parse" | "budget" | "context";
  message: string;
  endpoint?: string;
}
```

### 4.2 Provider interface (`src/layers/ai/providers/base.ts`)

```ts
export interface AIProvider {
  readonly name: "anthropic" | "openai" | "mock";

  /**
   * Generate a structured finding report using the provider's native
   * structured-output mechanism (forced tool use / json_schema strict).
   * Returns RAW provider output — orchestrator validates via Zod.
   */
  generateFindings(request: GenerateRequest): Promise<GenerateResponse>;

  /**
   * Estimate tokens for a request without making an API call.
   * Used by dry-run and budget pre-check.
   */
  estimateTokens(request: GenerateRequest): TokenEstimate;
}

export interface GenerateRequest {
  systemPrompt: string;
  projectSummary: string;              // cached prefix (Anthropic)
  userPrompt: string;                  // per-endpoint body
  toolDefinition: ToolDefinition;
  maxInputTokens: number;
  maxOutputTokens: number;
}

export interface GenerateResponse {
  rawFindings: unknown[];              // orchestrator validates each
  usage: AIUsage;
  stopReason: "end_turn" | "tool_use" | "max_tokens" | "error";
  rawError?: string;
}

export interface TokenEstimate {
  inputTokens: number;
  estimatedCostUsd: number;
}

export interface ToolDefinition {
  name: "report_findings";
  description: string;
  schema: object;                      // JSON schema derived from Zod
}

export interface ProviderPricing {
  inputPerMTokUsd: number;             // per 1M input tokens
  outputPerMTokUsd: number;
  cacheReadPerMTokUsd: number;         // ~10% of input on Anthropic
  cacheWritePerMTokUsd: number;        // ~125% of input on Anthropic
}
```

### 4.3 `AIFinding` Zod schema (`src/layers/ai/schema.ts`)

```ts
import { z } from "zod";

export const AIFindingSchema = z.object({
  ruleId: z.string().regex(/^AI-[A-Z]+-\d{3}$/),
  domain: z.enum([
    "secrets-exposure", "input-injection", "auth-access-control",
    "file-upload", "api-security", "cryptography", "supply-chain",
    "infrastructure", "business-logic", "logging-monitoring",
  ]),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  confidence: z.enum(["high", "medium", "low"]),  // NOT "confirmed"
  title: z.string().min(10).max(200),
  description: z.string().min(20).max(2000),
  evidence: z.array(z.object({
    file: z.string(),
    line: z.number().int().positive().optional(),
    snippet: z.string().max(500).optional(),
  })).min(1),
  remediation: z.string().min(20).max(1000),
  reasoning: z.string().min(20).max(2000),
});

export type AIFinding = z.infer<typeof AIFindingSchema>;
```

### 4.4 Adapter: `AIFinding → Finding`

```ts
function aiToFinding(ai: AIFinding): Finding {
  return {
    id: `ai:${ai.ruleId}:${ai.evidence[0].file}:${ai.evidence[0].line ?? 0}`,
    domain: ai.domain,
    severity: ai.severity,
    confidence: ai.confidence,
    title: ai.title,
    description: ai.description,
    evidence: ai.evidence.map(e => ({
      ...e,
      context: { reasoning: ai.reasoning },
    })),
    remediation: ai.remediation,
    references: [],
    layer: "ai",
    ruleId: ai.ruleId,
  };
}
```

---

## 5. Prompts & Context Strategy

### 5.1 Project summary (cached prefix)

Built once per scan from `ProjectModel`. Used as the cached prefix across every per-endpoint call. On Anthropic this is the cache breakpoint; on OpenAI the ≥1024-token automatic cache picks it up.

```
You are analyzing a {stack} project for security vulnerabilities.

PROJECT: {meta.name}
STACK: {meta.stack} · {meta.framework} · {meta.language}

ROUTES ({routes.length} total, {apiCount} API):
  {method} {path} → {file} (auth: {hasAuthCheck})
  ... (first 50; overflow marker if more)

DATA MODELS:
  {name} ({source}, RLS: {hasRls})

AUTH FLOWS:
  {type} in {file}

SECURITY-RELEVANT DEPENDENCIES:
  {name}@{version}

INFRA:
  Security headers present: {list or "none"}
  Middleware: {present/absent}
  Supabase config: {present/absent}

Your job is to identify REAL security vulnerabilities — not theoretical risks.
Focus on: business logic flaws, authorization bypasses, IDOR, injection, unsafe flows.
Be conservative: prefer "no finding" over a low-confidence guess.
Only report issues where you can cite specific file+line evidence.
Cap your confidence at "high" — never claim "confirmed".
```

**Truncation:** if `routes.length > 50`, first 50 + `... and {n} more`. The per-endpoint prompt always has the full target route.

### 5.2 Per-endpoint prompt (the workhorse)

```
ENDPOINT: {method} {path}
FILE: {endpoint.file}
AUTH CHECK: {present/absent}
VALIDATION: {validationLibrary or "none"}
SERVICE ROLE: {"YES (bypasses RLS!)" or "no"}

HANDLER CODE:
```{language}
{fileContent}
```

ADJACENT FILES (imported helpers):
{for each adjacent file}
FILE: {path}
```{language}
{content}
```

Analyze this endpoint for security vulnerabilities. Consider:
- Authorization bypass (missing or weak auth check)
- IDOR / insecure direct object reference
- Input validation gaps
- Secrets exposure
- Unsafe defaults (service role used when user role would suffice)
- Missing rate limiting on sensitive actions
- Information disclosure in error responses

For EACH finding, call the `report_findings` tool with:
- Specific file + line number from the code above
- A snippet showing the problem
- Reasoning that explicitly cites what would have to be true for this to be exploitable
- Remediation pointing to a concrete change

Do not report:
- Theoretical issues with no concrete evidence in the code
- Issues where "depends on configuration" is the main caveat
- Things the static rules layer would catch (hardcoded secrets, obvious SQL concat)

If the endpoint has no issues, call `report_findings` with an empty array.
```

### 5.3 Context assembly (`context-builder.ts`)

For each endpoint, the context-builder collects, in priority order (highest first):

1. **Handler file** (always). Never dropped.
2. **Validation schemas** — Zod/Yup imports.
3. **Auth helpers** — imports matching `auth`, `session`, `user`.
4. **Data models** — if handler references a known table name, attach schema/RLS from `model.dataModels`.
5. **Adjacent files** — local imports (non-`node_modules`), depth ≤ 2, count ≤ 5.

**Per-endpoint hard cap: 8000 input tokens** (from `AIConfig.maxTokensPerEndpoint`). If assembly exceeds it, drop items in **reverse** priority order — least-important first — until under cap. Handler itself is never dropped. If handler alone exceeds cap, emit `AIError { kind: "context" }` and skip that endpoint.

### 5.4 Stage A prompt (`--ai-deep` only)

```
You are doing a project-wide security triage on a {stack} project.

{projectSummary}  ← full project summary from 5.1

Identify the TOP security risks in this project WITHOUT analyzing individual
files yet. Use only the summary above.

For EACH risk, call `report_project_risks` with:
- The affected domain
- A description of the risk pattern
- Which endpoints are most likely affected (cite paths from the route list)
- Severity estimate

Then produce a priority order: list the endpoint paths you'd analyze first,
most-risky to least-risky. Include EVERY API endpoint in the list.
```

**Stage A is advisory-only.** Its output feeds `StageARiskSummary.priorityOrder` back into the orchestrator. The per-endpoint loop processes endpoints in Stage-A priority order instead of file-system order. Stage A does **not** tell Stage B what to find — Stage B always sees real code, not a framing from Stage A. This is the key defense against compounding hallucination.

**Stage A failure handling:** if Stage A errors, log warning, fall back to file-system priority order, continue per-endpoint loop normally.

---

## 6. Budget, Caching, Cost Controls

### 6.1 `BudgetTracker` class

```ts
export class BudgetTracker {
  private totalInput = 0;
  private totalOutput = 0;
  private totalCacheRead = 0;
  private totalCacheWrite = 0;

  constructor(
    private readonly maxCostUsd: number,
    private readonly pricing: ProviderPricing,
  ) {}

  recordUsage(usage: AIUsage): void;            // accumulate
  currentCostUsd(): number;                     // running total
  wouldExceed(estimate: TokenEstimate): boolean;// pre-flight check
  exhausted(): boolean;                         // currentCost >= maxCostUsd
  summary(): AIUsage;                           // for final report
}
```

Pricing lives with each provider (`PRICING` constant keyed by model name in `anthropic.ts` and `openai.ts`). Mock pricing is zero.

### 6.2 Enforcement loop

The pseudocode below is shown sequentially for clarity. The real orchestrator runs up to `AIConfig.concurrency` endpoints in parallel via a bounded worker pool. Budget checks run on every worker before its call; `BudgetTracker` is shared and its accumulator is atomic under JS's single-threaded event loop (no mutex needed). If one worker hits `exhausted`, the remaining work is drained without new calls.

```
for each endpoint in priorityOrder:
  if budget.exhausted():
    emit warning, record "budgetExhausted: true"
    skip all remaining endpoints
    break

  context = buildContext(endpoint)
  if context is null:
    record AIError(context), continue

  estimate = provider.estimateTokens(request)

  if budget.wouldExceed(estimate):
    emit warning, record "budgetExhausted: true"
    skip this + remaining endpoints
    break

  try:
    response = await provider.generateFindings(request)
    budget.recordUsage(response.usage)
    for rawFinding in response.rawFindings:
      try:
        validated = AIFindingSchema.parse(rawFinding)
        findings.push(aiToFinding(validated))
      except ZodError:
        record AIError(parse), continue  // lose one finding, keep others
  except ProviderError:
    record AIError(provider), continue    // lose whole endpoint, keep scan
```

**Pre-flight estimate prevents overshoot:** `wouldExceed` runs before the call, so a `--ai-max-cost 1.00` run cannot end at $1.05.

### 6.3 Prompt caching

**Anthropic** (explicit cache breakpoints):
```ts
{
  system: [
    { type: "text", text: PERMANENT_SYSTEM_PREAMBLE },
    { type: "text", text: projectSummary, cache_control: { type: "ephemeral" } },
  ],
  messages: [{ role: "user", content: perEndpointPrompt }],
  tools: [reportFindingsTool],
  tool_choice: { type: "tool", name: "report_findings" },
}
```

First call: cache write cost (~125% of input rate). Subsequent calls in the same scan: cache read (~10% of input rate). 5-minute TTL keeps the cache warm across a steady stream of endpoint calls.

**OpenAI** (automatic caching for ≥1024-token prefixes): no payload changes. Track cache stats from `usage.prompt_tokens_details.cached_tokens`.

Measured savings (estimated): 20-endpoint project drops from ~$1.50 to ~$0.28 with caching.

### 6.4 Dry-run mode (`--ai-dry-run`)

Flow:

1. runRecon (same as normal)
2. runRules (same as normal)
3. `buildContext()` for every endpoint
4. `provider.estimateTokens()` for every endpoint
5. Sum estimates, compute cost using provider pricing
6. Print:
   ```
   AI Dry Run
   ──────────
   Endpoints to analyze: 23
   Project summary tokens: 4,120 (cached after first call)
   Per-endpoint avg tokens: 5,200
   Total input tokens: ~123,720
   Output tokens (est): ~18,400
   Estimated cost: $0.34 (Anthropic claude-sonnet-4-6)
   Budget cap: $2.00
   Status: within budget

   Run without --ai-dry-run to execute.
   ```
7. Exit 0, no API calls made.

Dry run runs without `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` set — provider constructors are allowed to defer env checks for dry-run mode.

### 6.5 Final cost report

After every real run with `--ai`:

```
AI Analysis
───────────
Endpoints analyzed: 23 / 23
Findings:           7 (high: 2, medium: 4, low: 1)
Errors:             0

Tokens:
  Input:       124,318
  Cached read: 95,640 (cache hit rate: 77%)
  Output:      18,412

Cost estimate: $0.28 (under $2.00 cap)
Duration: 42s
```

Appended to terminal output. JSON output gets `runInfo.ai`. HTML output gets a cost badge.

### 6.6 Defaults

```
maxCostUsd            2.00    flag: --ai-max-cost
maxTokensPerEndpoint  8000    (config only, not flag-exposed)
concurrency           3       flag: --ai-concurrency
model                 "claude-sonnet-4-6"   flag: --ai-model
provider              "anthropic"           flag: --ai-provider
```

### 6.7 Failure mode table

| Failure | Handling |
|---------|----------|
| Provider API key missing | Fail fast at `runAI` start. Clear error + setup link. Exit code 2. |
| Provider 5xx | Retry 3x with exp backoff (1s/2s/4s). On final failure: record AIError, skip endpoint, continue. |
| Rate limit (429) | Honor `Retry-After`, up to 60s total. If exceeded: skip + continue. |
| Zod parse failure | Lose one finding, keep rest from same endpoint. Record AIError(parse). |
| Malformed tool_use response | Same as parse failure. |
| Per-call timeout (60s hard) | Skip endpoint. Record AIError(provider). |
| Budget exhausted mid-scan | Skip remaining endpoints. Return partial findings. `budgetExhausted: true`. Print warning. |
| Context build failure | Skip endpoint. Record AIError(context). |
| Stage A failure | Log warning. Fall back to file-system order. Continue per-endpoint loop. |

---

## 7. CLI & Config Integration

### 7.1 New flags on `scan` (and mirrored on `diff`)

```
--ai                         Enable AI layer (opt-in)
--ai-deep                    Enable Stage A project-wide risk pass
--ai-dry-run                 Estimate cost only, make no API calls
--ai-provider <name>         anthropic | openai | mock (default: anthropic)
--ai-model <id>              Override default model for chosen provider
--ai-max-cost <usd>          Hard budget cap in USD (default: 2.00)
--ai-concurrency <n>         Parallel endpoint analyses (default: 3)
```

### 7.2 `.sentinelrc.json` config additions

```json
{
  "ai": {
    "enabled": false,
    "provider": "anthropic",
    "model": "claude-sonnet-4-6",
    "deep": false,
    "maxCostUsd": 2.00,
    "maxTokensPerEndpoint": 8000,
    "concurrency": 3
  }
}
```

**Precedence** (resolved in `loadConfig`): CLI flag > env var > config file > default.

**Env vars:**
- `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` — consumed by providers, never logged
- `SENTINEL_AI_ENABLED=1` — equivalent to `--ai`
- `SENTINEL_AI_MAX_COST=5.00` — equivalent to `--ai-max-cost 5.00`

### 7.3 `scan.ts` wiring

```ts
import { runAI } from "../layers/ai/index.js";

export interface ScanOptions {
  // existing...
  ai?: boolean;
  aiDeep?: boolean;
  aiDryRun?: boolean;
  aiProvider?: "anthropic" | "openai" | "mock";
  aiModel?: string;
  aiMaxCost?: number;
  aiConcurrency?: number;
}

export async function runScan(options: ScanOptions): Promise<number> {
  const config = await loadConfig(options.path);
  const model = await runRecon(options.path, config.exclude);
  const ruleFindings = await runRules(model);

  let aiResult: AIRunResult | null = null;
  if (options.ai || config.ai.enabled) {
    const aiConfig = mergeAIConfig(config.ai, options);
    aiResult = await runAI(model, aiConfig);
    model.findings.push(...aiResult.findings);
  }

  // existing output logic, with runInfo.ai = aiResult?.usage
}
```

No changes to `runRecon` or `runRules`. AI layer is a pure addition.

### 7.4 Output format additions

**Terminal:** cost report appended (see 6.5).

**JSON:** `runInfo.ai` added:
```json
{
  "runInfo": {
    "recon_ms": 340,
    "rules_ms": 1240,
    "ai_ms": 42000,
    "ai": {
      "enabled": true,
      "provider": "anthropic",
      "model": "claude-sonnet-4-6",
      "deep": false,
      "endpointsAnalyzed": 23,
      "endpointsSkipped": 0,
      "budgetExhausted": false,
      "usage": { ... },
      "errors": []
    }
  }
}
```

**HTML:** cost badge in header `[AI: $0.28 · 23 endpoints]`.

Findings already render with `layer` tagging — no changes to formatter internals. AI findings file under an "AI" section in terminal/HTML by existing layer-grouping logic.

### 7.5 `diff` command

AI findings' `ruleId` starts with `AI-`, so they diff naturally alongside rule findings. Addition: diff output splits new findings by layer so users see "3 new rule findings, 2 new AI findings" instead of one undifferentiated count.

### 7.6 Provider selection

```ts
function selectProvider(config: AIConfig, isTest: boolean): AIProvider {
  if (config.provider === "mock" || isTest) return new MockProvider();
  if (config.provider === "anthropic") {
    requireEnv("ANTHROPIC_API_KEY");  // unless dryRun
    return new AnthropicProvider(config.model);
  }
  if (config.provider === "openai") {
    requireEnv("OPENAI_API_KEY");     // unless dryRun
    return new OpenAIProvider(config.model);
  }
  throw new Error(`Unknown AI provider: ${config.provider}`);
}
```

`requireEnv` fails fast with a formatted error pointing at `creds set anthropic-api-key` for local users. No silent undefined keys.

---

## 8. Testing Strategy

### 8.1 Mock provider (default, always on)

`MockProvider` dispatches canned responses by request key:

```ts
const mock = new MockProvider({
  "/api/users/[id]": {
    rawFindings: [{ /* AIFinding-shaped */ }],
    usage: { inputTokens: 5000, outputTokens: 400, cacheReadTokens: 4000, cacheWriteTokens: 0, estimatedCostUsd: 0 },
    stopReason: "tool_use",
  },
  "/api/public/stats": { rawFindings: [], usage: { /* ... */ }, stopReason: "tool_use" },
});
```

**Invariants:**
- No network access (fails loudly if real `fetch` is called)
- Deterministic token counts from the dispatch map
- Can inject failures (`stopReason: "error"`, malformed findings) to exercise error paths
- Zero cost in all calculations

### 8.2 Unit test coverage

| File | Asserts |
|------|---------|
| `orchestrator.test.ts` | endpoint loop order, concurrency respected, budget exhaustion handled, graceful skipping on context/provider/parse errors, `AIFinding → Finding` adapter, no mutation of `ProjectModel`, Stage A happy path + fallback |
| `providers/anthropic.test.ts` | messages payload shape with cache_control, forced tool_choice, schema passed correctly, stop_reason parsing, cache token accounting, retry with exponential backoff, 429 handling with Retry-After, 401/403 fast-fail, `estimateTokens` without API call |
| `providers/openai.test.ts` | `response_format json_schema strict`, cached token stats, retry/backoff, same behavioral guarantees |
| `providers/mock.test.ts` | dispatch map lookup, unknown-key failure, network-access refusal |
| `context-builder.test.ts` | handler always included, adjacent file resolution depth ≤ 2 count ≤ 5, data model attachment, validation schema attachment, token budget respected, handler-too-large emits context error |
| `schema.test.ts` | valid findings pass, confidence: "confirmed" rejected, empty evidence rejected, bad ruleId format rejected, length bounds enforced, unknown domain rejected, `aiToFinding` round-trip |
| `budget.test.ts` | accumulation math, cost calculation with pricing, `wouldExceed` pre-flight, `exhausted` at exactly `maxCostUsd`, cache tokens priced at cache rate |
| `dry-run.test.ts` | runs recon + rules + context build with no provider calls, no API key required, output format matches spec, exit 0 |

### 8.3 Integration tests

**`tests/integration/ai-scan.test.ts`:**
- Runs `sentinel scan --ai --ai-provider mock` against `tests/fixtures/ai-scan/`
- Verifies AI findings appear tagged `layer: "ai"`
- Verifies rule findings still appear (AI is additive)
- Verifies `runInfo.ai` present in JSON output
- Verifies cost report section in terminal output
- Verifies exit code respects `--fail-on` with AI findings
- Verifies `--ai-dry-run` makes zero mock provider calls

**`tests/integration/ai-diff.test.ts`:**
- Two scans with different mock dispatch maps
- `sentinel diff` splits new findings by layer

### 8.4 Live tests (gated)

`tests/layers/ai/live/smoke.test.ts`:
- Gated by `RUN_AI_LIVE_TESTS=1`. Skipped silently in normal CI.
- Runs real `sentinel scan --ai --ai-provider anthropic` against `tests/fixtures/ai-scan/`
- Hard cap `--ai-max-cost 0.25`
- Asserts: no crashes, returns `AIRunResult`, `budgetExhausted: false`
- Asserts: ≥1 finding (sanity check real model isn't broken)
- Asserts: usage token math matches provider-reported values
- Same test for OpenAI, gated by its own provider env var

**Manual run command:**
```bash
ANTHROPIC_API_KEY=xxx OPENAI_API_KEY=xxx RUN_AI_LIVE_TESTS=1 npm test -- tests/layers/ai/live
```

CI excludes `tests/layers/ai/live/**` by glob.

### 8.5 Fixture: `tests/fixtures/ai-scan/`

Minimal Next.js + Supabase project (~150 lines of code):

```
package.json              next + supabase deps
next.config.js
src/app/api/users/[id]/route.ts     IDOR-vulnerable (no ownership check)
src/app/api/public/stats/route.ts   clean (auth-less by design, info only)
src/app/api/config/route.ts         hardcoded API key (rule-layer target)
src/lib/auth.ts                     shared auth helper
src/lib/supabase.ts                 server + service role clients
```

Live tests burn <$0.10 per run at current pricing. Mock tests use the same fixture.

### 8.6 What is NOT tested

- Real AI finding *quality* — assertions verify wiring, not model behavior
- AI provider SDK internals — treated as trusted black boxes
- Cross-provider parity — expected to differ
- Token estimation accuracy — estimate is advisory; authoritative numbers come from provider usage fields

---

## 9. Open Questions

None blocking implementation. Recorded for the plan-writing phase and future cycles:

1. **Provider SDK choice** — use `@anthropic-ai/sdk` + `openai` npm packages, or hand-rolled fetch? Plan phase will decide. Default: SDKs (faster to ship, handles retries).
2. **Default model** — `claude-sonnet-4-6` recommended for first run; `claude-haiku-4-5` as a cheap alternative for CI pipelines. Plan phase will expose this as a first-class flag/config decision.
3. **`--ai-deep` Stage A cost** — not yet estimated. Plan phase should add a dry-run Stage A cost estimate as part of the initial implementation.

---

## 10. Out of Scope (Explicitly Deferred)

- **Probe layer**: separate spec, next cycle
- **Agent-style retrieval tools**: v0.4+ upgrade path
- **Multi-stage pipeline (Stage B validation, Stage C dedup)**: rejected; can be reconsidered once v0.3 has real usage data
- **Cross-file data-flow analysis for AI prompts**: adjacent-file bundling is approximate; deeper flow analysis belongs in the rule engine bucket
- **Streaming output**: providers support streaming; we use the sync API for simplicity in v0.3
- **Token-cost display per finding**: cost is reported per-scan only
- **AI-authored remediation PRs**: the AI returns remediation *text*, not code patches
- **Learning/feedback loop**: no "was this finding useful?" capture in v0.3

---

## 11. Success Criteria (reiteration)

Implementation is complete when:

- `sentinel scan --ai --ai-provider mock` runs end-to-end against `tests/fixtures/ai-scan/` without real API calls
- `sentinel scan --ai --ai-dry-run` prints a cost estimate and makes zero provider calls, with or without API keys set
- `sentinel scan --ai --ai-provider anthropic` against the fixture returns ≥1 finding under $0.25 (live, gated)
- Full test suite (81 existing + ~40 new) passes without live network
- AI findings flow through terminal / JSON / HTML / diff outputs tagged `layer: "ai"` with zero formatter changes
- A scan with `--ai` followed by a provider API crash leaves the user with a complete rule-layer scan + a clear warning (never a crashed sentinel)
- `BudgetTracker` prevents any run from exceeding `--ai-max-cost` by even one token, verified by unit tests
