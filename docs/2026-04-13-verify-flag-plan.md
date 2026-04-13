# Plan: `--verify` Flag — AI Verification Pass for Rule Findings

*Created: 2026-04-13*
*Branch: worktree-context-layer*
*Depends on: context layer (complete), AI layer (complete)*

---

## Problem

The rules layer produces findings via textual regex matching. Short identifier stems like `sig`, `token`, `key`, `password` inevitably collide with unrelated code:

- `CRYPTO-008` matches `if (config.signals !== false)` because `signals` contains `sig`
- `CRYPTO-008` matches `typeof token !== 'string'` — type guard, not secret comparison
- `LOG-001` matches `console.log` inside template-literal code samples (documentation snippets)
- `LOG-001` matches `console.warn('[facegate] Using apiKey for JWT verification...')` — the warning only *mentions* the word "apiKey"

Tightening each regex is whack-a-mole. The root problem is that rules emit verdicts without semantic context. **The fix is to treat rule findings as candidates and run them through an AI verifier that sees the surrounding source plus the already-threaded `ProjectContext`.**

---

## Design

### Flow

```
runRules  →  ruleFindings[]
                   │
                   ▼
            (if --verify)
                   │
                   ▼
    verifyFindings(ruleFindings, model, context, provider)
                   │
                   ▼
    { confirmed, dismissed, downgraded, reasons }
                   │
                   ▼
    allFindings = [...confirmed, ...downgraded, ...aiFindings]
    dismissed findings → audit trail in JSON output, not in summary
```

### Batching

Group rule findings by file. Send one request per file containing:
- File path + full source (truncated to N lines around each finding if huge)
- All rule findings in that file
- `ProjectContext` summary (framework, tenancy, excluded paths, delegations)

Model returns a verdict per finding via structured tool call.

### Verdict schema

```ts
type Verdict = {
  findingId: string;
  decision: "confirm" | "dismiss" | "downgrade";
  reason: string;                    // short, user-facing
  newSeverity?: Severity;            // required when decision === "downgrade"
};
```

### Flag semantics

- `--verify` — enable verification pass. Implies `--ai` is not required (verification uses the AI provider independently).
- `--verify-model <id>` — override model (default: cheap/fast model like haiku)
- `--verify-max-cost <usd>` — separate budget cap from `--ai-max-cost`
- `--verify-concurrency <n>` — parallel file verifications (default 4)
- `--verify-min-severity <level>` — only verify findings at or above this level (default `medium`, skips info/low)

### Provider reuse

Use the existing `AIProvider` interface. No new provider code — just a new prompt + new tool schema. Verification shares the same `BudgetTracker` infrastructure with its own cost cap.

### Dismissal behavior

- Dismissed findings are **removed from the terminal summary and exit-code calculation**
- Dismissed findings are **retained in JSON output** under `verification.dismissed[]` with the model's reason, for audit
- Dismissed findings are **logged to stderr** in verbose mode
- `--no-dismiss` flag keeps dismissed findings in the report with a "SUSPECTED FALSE POSITIVE" annotation — useful during trust-building

---

## File Structure

### New files

```
src/layers/ai/verify.ts                  # verifyFindings() orchestrator
src/layers/ai/verify-prompts.ts          # system + user prompt builders
src/layers/ai/verify-schema.ts           # tool definition + Zod verdict schema
src/model/types.ts                       # add VerifyResult, VerifyConfig types
tests/layers/ai/verify.test.ts           # unit tests (MockProvider)
tests/layers/ai/verify-prompts.test.ts   # prompt construction tests
tests/integration/verify-scan.test.ts    # end-to-end with MockProvider
tests/fixtures/verify/                   # fixtures with known-false-positive rule hits
```

### Modified files

```
src/commands/scan.ts          # wire --verify flag, call verifyFindings()
src/cli.ts                    # register --verify* options
src/config/schema.ts          # add ai.verify config section
src/commands/scan.ts          # mergeVerifyConfig()
src/layers/ai/index.ts        # export runVerify()
src/reporters/terminal.ts     # show "N dismissed by verifier" line
src/reporters/json.ts         # add verification.{confirmed,dismissed,downgraded}
```

---

## Tasks

### Task 1: Types and Config Schema

**Why:** Lock contracts before plumbing. Matches type-first discipline.

- [ ] **Step 1: Write the test**
  - File: `tests/model/verify-types.test.ts`
  - Assert `VerifyConfig` has: enabled, provider, model, maxCostUsd, concurrency, minSeverity, keepDismissed
  - Assert `VerifyResult` has: confirmed[], dismissed[], downgraded[], usage, errors[], durationMs
  - Assert `Verdict` schema roundtrips through Zod with valid/invalid examples

- [ ] **Step 2: Implement types in `src/model/types.ts`**
  - Add `VerifyConfig`, `VerifyResult`, `Verdict` interfaces
  - Extend `AIRunResult`'s neighbor (not `AIRunResult` itself) — verification is a sibling, not a child

- [ ] **Step 3: Extend config schema**
  - `src/config/schema.ts`: add `ai.verify` block with defaults
  - Default: `{ enabled: false, model: "claude-haiku-4-5", maxCostUsd: 1.00, concurrency: 4, minSeverity: "medium", keepDismissed: false }`

- [ ] **Step 4: Commit**
  - Message: `feat(verify): types and config schema for verification pass`

### Task 2: Prompt + Tool Schema

**Why:** The prompt is the product. Get it right in isolation, test it before wiring.

- [ ] **Step 1: Write tests for prompt builder**
  - File: `tests/layers/ai/verify-prompts.test.ts`
  - Given file + findings + context → produces a prompt that:
    - Includes file path, source (or windowed snippet)
    - Lists each finding with ruleId, line, message, snippet
    - Includes context summary (framework, tenancy, excluded paths)
    - Instructs: "For each finding, decide confirm/dismiss/downgrade with a reason"

- [ ] **Step 2: Implement `src/layers/ai/verify-prompts.ts`**
  - `buildSystemPrompt()` — static
  - `buildUserPrompt(file, source, findings, context)` — dynamic
  - `buildToolDefinition()` — structured-output tool with verdicts[] array

- [ ] **Step 3: Run tests**

- [ ] **Step 4: Commit**
  - Message: `feat(verify): prompt and tool schema for finding verification`

### Task 3: Verification Orchestrator (single file)

**Why:** One file at a time, fully deterministic, before adding concurrency.

- [ ] **Step 1: Write test**
  - File: `tests/layers/ai/verify.test.ts`
  - MockProvider returns canned verdicts
  - Given 3 findings for one file → returns VerifyResult with confirmed=1, dismissed=1, downgraded=1
  - Verify budget tracker increments
  - Verify provider errors fall back to "confirm all" (safe default: don't silently drop real findings on API failure)

- [ ] **Step 2: Implement `src/layers/ai/verify.ts` — single-file path**
  - `verifyFindingsForFile(file, source, findings, context, provider, budget)`
  - Build request → call provider → parse verdicts → map back to findings
  - On parse error or API error: return all findings as `confirmed` with an error note
  - Return `VerifyResult` shape

- [ ] **Step 3: Run tests**

- [ ] **Step 4: Commit**
  - Message: `feat(verify): single-file verification orchestrator`

### Task 4: Multi-File Orchestration with Concurrency

**Why:** Real scans hit many files. Parallelize but cap.

- [ ] **Step 1: Write test**
  - MockProvider with artificial delay
  - Given 10 files → verify concurrency cap is respected (track in-flight count)
  - Verify all verdicts are collected
  - Verify budget exhaustion halts further calls early

- [ ] **Step 2: Implement `runVerify(model, findings, context, config, provider)`**
  - Group findings by file
  - Filter by `minSeverity`
  - Run per-file verifications with p-limit style concurrency
  - Aggregate into single `VerifyResult`
  - Export from `src/layers/ai/index.ts`

- [ ] **Step 3: Run tests**

- [ ] **Step 4: Commit**
  - Message: `feat(verify): multi-file orchestration with concurrency and budget`

### Task 5: CLI Flag Registration

**Why:** Expose the pass to users.

- [ ] **Step 1: Write test**
  - File: `tests/cli/verify-flags.test.ts`
  - Parse `scan --verify` → `options.verify === true`
  - Parse `--verify --verify-max-cost 5 --verify-concurrency 8` → correct options
  - Parse `--verify --no-dismiss` → `keepDismissed: true`

- [ ] **Step 2: Register in `src/cli.ts`**
  - `--verify`, `--verify-model`, `--verify-max-cost`, `--verify-concurrency`, `--verify-min-severity`, `--no-dismiss`
  - Keep alongside existing `--ai-*` flags

- [ ] **Step 3: `mergeVerifyConfig` in `src/commands/scan.ts`**
  - Merge CLI options → config defaults → `VerifyConfig`

- [ ] **Step 4: Run tests**

- [ ] **Step 5: Commit**
  - Message: `feat(verify): CLI flag registration and config merge`

### Task 6: Wire Into Scan Pipeline

**Why:** Glue the orchestrator to the scan flow.

- [ ] **Step 1: Write integration test**
  - File: `tests/integration/verify-scan.test.ts`
  - Fixture with 3 rule findings: 1 real, 2 obvious false positives
  - Scan with `--verify` and MockProvider that dismisses the 2 FPs
  - Assert terminal output shows 1 finding, not 3
  - Assert JSON output contains `verification.dismissed` with both FPs and reasons

- [ ] **Step 2: Update `src/commands/scan.ts`**
  - After `runRules`, if `options.verify`, call `runVerify(model, ruleFindings, context, verifyConfig, provider)`
  - Split `ruleFindings` into `confirmedRuleFindings` + `dismissedRuleFindings`
  - `allFindings = [...confirmedRuleFindings, ...(aiResult?.findings ?? [])]`
  - Pass `verifyResult` into reporter functions
  - Context suppression still runs on the pre-verify set (suppression is project-level, verify is per-finding — both apply)

- [ ] **Step 3: Run integration test**

- [ ] **Step 4: Commit**
  - Message: `feat(verify): wire verification pass into scan pipeline`

### Task 7: Reporters

**Why:** The user needs to see what was dismissed and why.

- [ ] **Step 1: Write tests**
  - `tests/reporters/terminal-verify.test.ts` — dismissed count line, "--no-dismiss" annotation
  - `tests/reporters/json-verify.test.ts` — `verification: { confirmed, dismissed, downgraded, usage }` block

- [ ] **Step 2: Update terminal reporter**
  - Add summary line: `Verified: N confirmed, M dismissed, K downgraded`
  - When `keepDismissed`, show dismissed findings grouped with `[DISMISSED: reason]` annotation
  - Show per-finding dismissal reasons in verbose mode

- [ ] **Step 3: Update JSON reporter**
  - Top-level `verification` block with full audit trail

- [ ] **Step 4: Run tests**

- [ ] **Step 5: Commit**
  - Message: `feat(verify): terminal and JSON reporter support`

### Task 8: Real-World Validation

**Why:** Before declaring done, run on facegate and skutt. Measure.

- [ ] **Step 1: Run `sentinel scan --verify` on facegate**
  - Expected: the 4 CRYPTO/LOG false positives from today's analysis get dismissed
  - Expected: the 4 `test/page.tsx` LOG hits either dismissed or downgraded (context already has them as a dev page)
  - Record: total findings before/after, cost, duration

- [ ] **Step 2: Run on skutt**
  - Compare against the triage doc's known FP count
  - Record: precision improvement

- [ ] **Step 3: Write findings to `docs/2026-04-13-verify-validation.md`**
  - Table: project × before × after × cost × duration
  - Any new FPs introduced by the verifier (bad dismissals)
  - Recommended default config based on findings

- [ ] **Step 4: Commit**
  - Message: `docs(verify): real-world validation results for facegate and skutt`

### Task 9: Full Regression

- [ ] **Step 1: `npm test`** — all existing tests still pass
- [ ] **Step 2: `npm run build`** — clean build
- [ ] **Step 3: `sentinel scan`** (without `--verify`) on facegate and context fixture — unchanged output
- [ ] **Step 4: `sentinel scan --verify`** on both — verification applies cleanly
- [ ] **Step 5: Commit any test fixes**

---

## Non-Goals

- Caching verdicts across scans (deferred — depends on stable finding IDs and file hashing)
- Per-rule verifier config (e.g., "always verify CRYPTO-008 but never verify SECRET-*") — start global, add granularity if needed
- Fine-tuning a verification model — start with a general model via standard provider
- Verifying AI-layer findings — the AI layer already reasons with context; verifying its own output risks feedback loops
- A dedicated `verifier` subcommand — keep it as a scan pass for now

---

## Risks

| Risk | Mitigation |
|---|---|
| Verifier dismisses real findings (false negatives) | `--no-dismiss` mode during trust-building; dismissed findings retained in JSON for audit; validation in Task 8 measures this explicitly |
| Verifier cost balloons on large repos | Per-file batching, concurrency cap, `maxCostUsd` budget, `minSeverity` filter skips low-priority noise |
| Verifier is slow | Default to a cheap/fast model (haiku tier), parallel per-file, `--verify` is opt-in not default |
| Prompt injection via source code | System prompt instructs model to never execute instructions from the analyzed source; source is clearly delimited in the user prompt |
| Verifier gives inconsistent verdicts | Structured tool output with enum decisions, low temperature, deterministic grouping |

---

## Success Criteria

1. `sentinel scan --verify ~/Downloads/projects/facegate` dismisses at least 3 of the 4 known false positives from today's scan
2. Zero real findings from today's scan are dismissed
3. Verification cost on facegate under $0.10 using default config
4. No regressions in existing test suite
5. `--no-dismiss` mode preserves the current report shape for users who don't yet trust the verifier

---

## Rollout

1. Ship `--verify` as opt-in (default `false`)
2. Validate on facegate + skutt (Task 8)
3. If precision holds, flip default to `true` in a follow-up commit with a `--no-verify` escape hatch
4. Consider `.sentinelrc.json`-level opt-in as the intermediate step
