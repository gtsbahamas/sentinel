# `--verify` Real-World Validation

*Run: 2026-04-13*
*Branch: worktree-context-layer*
*Plan: `docs/2026-04-13-verify-flag-plan.md` — Task 8*

---

## Summary

The verification pass was run against two real projects with `--verify-model claude-haiku-4-5` and a `$2.00` budget cap. It cleanly dismissed every known false positive from the facegate manual triage and eliminated **34.7% of skutt findings** automatically — at a combined cost of **$0.22** across both scans.

Two real bugs in existing provider code were surfaced during this validation and fixed as part of Task 8.

---

## facegate

| Metric | Baseline | After `--verify` | Delta |
|---|---:|---:|---:|
| Total findings | 12 | 6 | **-50%** |
| High severity | 8 | 0 | **-100%** |
| Medium severity | 4 | 2 | **-50%** |
| Low severity | 0 | 4 | +4 (downgraded from test page) |

**Verifier metrics:** 7 files processed, 12 findings sent to AI, 6 dismissed, 4 downgraded, 2 confirmed, 0 errors, **$0.0330**, **4.7s**.

### Verdicts on known false positives from the 2026-04-13 manual triage

All 4 originally-identified false positives were **dismissed with on-point reasoning**:

| Finding | Our manual verdict | Haiku verdict | Model reasoning |
|---|---|---|---|
| `CRYPTO-008` `facegate-client.ts:51` — `if (config.signals !== false)` | False positive (boolean check) | **dismiss** | "Checking a boolean configuration flag, not comparing a cryptographic secret; 'signals' is a non-secret config" |
| `CRYPTO-008` `api/auth/session/route.ts:9` — `typeof token !== 'string'` | False positive (type guard) | **dismiss** | "Type-guard check (typeof token !== 'string'), not a secret comparison; the rule pattern matched the identifier" |
| `LOG-001` `snippets.ts:26` — `console.log('Authenticated:', ...)` | False positive (template literal code example) | **dismiss** | "This is a code snippet example string returned by a utility function, not actual production logging" |
| `LOG-001` `session.ts:54` — `console.warn('[facegate] Using apiKey ...')` | False positive (warning message only mentions 'apiKey' in text) | **dismiss** | "The log message only references 'apiKey' as a label/advice string, not the actual apiKey value itself" |

### Bonus dismissals (not in the original manual analysis)

The model caught two additional real FPs I missed during the triage:

| Finding | Haiku verdict | Reasoning |
|---|---|---|
| `LOG-008` `facegate-client.ts:137` — empty catch block | **dismiss** | "Empty catch intentionally suppresses expected errors from localStorage in SSR environments where it may not be available" |
| `INFRA-006` `qr.ts:56` — plain HTTP URL | **dismiss** | "'http://' is part of an XML namespace URI declaration (xmlns), not a reference to an actual HTTP resource" |

### Downgrades

All 4 `LOG-001` findings on `packages/website/src/app/test/page.tsx` were **downgraded from high → low** with the reasoning "This is a test/dev-only page where logging session info is intended for debugging in a non-sensitive context."

This is exactly the behavior the `downgrade` verdict was designed for: the underlying pattern is real (logging session objects), but severity should reflect that the code lives in a dev-only path.

### Remaining confirms

The 2 remaining findings are both `INFRA-006` on `packages/fairness/src/datasets/lfw.ts:24,25` — plain HTTP URLs for dataset downloads. The model confirmed these with a caveat: "Plain HTTP URL is used for downloading a public dataset without HTTPS... this is a non-critical use case." Correct call — the finding is real, but severity could arguably drop to medium. Future work: let the model downgrade even when confirming the issue type.

### Success criteria check

| Criterion | Target | Actual | Result |
|---|---|---|---|
| Dismiss ≥3 of 4 known FPs | 3 | 4 | ✅ |
| Zero real findings dismissed | 0 | 0 | ✅ |
| Verification cost under $0.10 | < $0.10 | $0.0330 | ✅ |

---

## skutt

| Metric | Baseline | After `--verify` | Delta |
|---|---:|---:|---:|
| Total findings | 202 | 132 | **-34.7%** |
| Critical | 0 | 0 | 0 |
| High | 75 | 24 | **-68%** |
| Medium | 31 | 8 | **-74%** |
| Low | 4 | 8 | +4 (downgraded) |
| Info | 92 | 92 | 0 (below minSeverity threshold, passed through) |

**Verifier metrics:** 48 files processed, 83 findings sent to AI (202 − 92 info − 27 below threshold / no file evidence), 70 dismissed, 6 downgraded, 126 confirmed, 1 error, **$0.1906**, **26s**, budget not exhausted.

### Context

The manual triage doc (`docs/skutt-triage.md`) records a previous reduction from 176 → 14 high-priority findings via human review. The automated verifier achieves 75 → 24 high findings (51 removed) with no human in the loop, in 26 seconds, for under 20 cents.

The verifier is not a replacement for deep manual triage — the human reduction reached 14 while the automated pass stops at 24. But the verifier eats the low-hanging fruit (substring-match false positives, context-dependent dismissals, dev-path downgrades) without burning engineering time, leaving the residual ambiguous cases for a human.

### Success criteria check

| Criterion | Target | Actual | Result |
|---|---|---|---|
| Meaningful FP reduction | — | 70 dismissed + 6 downgraded | ✅ |
| Cost under $0.10 per scan | < $0.10 | $0.1906 | ❌ (double budget; still well under the $2.00 cap) |
| No real findings dismissed | — | Not manually audited (too many) | ⚠ follow-up audit needed |

---

## Bugs surfaced and fixed during Task 8

### Bug 1: Anthropic provider rejected verification calls

**Symptom:** Every verify call against facegate returned `400 system.1: cache_control cannot be set for empty text blocks`. The verifier's safe-confirm fallback fired on every file, resulting in all findings being preserved as "confirmed" despite the provider never successfully running.

**Root cause:** `src/layers/ai/providers/anthropic.ts` unconditionally pushed a `projectSummary` system block with `cache_control: ephemeral`. The verification pass does not use `projectSummary` (file context lives in the user prompt), so the block was always empty. Anthropic's API rejects `cache_control` on empty text blocks.

**Fix:** Only push the `projectSummary` system block when it has content. The cache behavior for existing AI-layer calls is unchanged.

### Bug 2: Both providers hardcoded `report_findings` tool extraction

**Symptom:** After fixing Bug 1, every verify file returned `parsed=0 candidates=N`. The model was calling the `report_verdicts` tool correctly but the provider extracted an empty array. Findings defaulted to "confirm with reason: no verdict returned" via the safety fallback.

**Root cause:** Both `anthropic.ts` and `openai.ts` extracted tool output via a hardcoded `input.findings` key — appropriate for the `report_findings` tool but wrong for `report_verdicts` (which uses `input.verdicts`). The provider layer was tightly coupled to a single tool schema.

**Fix:** Tool-aware extraction in both providers. Each known tool name maps to its expected top-level array key:
- `report_findings` → `input.findings`
- `report_project_risks` → `input.projectRisks`
- `report_verdicts` → `input.verdicts`

Both bugs are fixed in the same commit as this validation doc.

---

## Recommended default config

Based on the validation results, the defaults in `CONFIG_DEFAULTS.ai.verify` (model `claude-haiku-4-5`, `maxCostUsd: 1.0`, `concurrency: 4`, `minSeverity: medium`, `keepDismissed: false`) hold up. Notes for tuning:

- **Haiku is precise enough.** Sonnet was tried on facegate and produced identical confirm-all results under the buggy provider path — not a fair test, but haiku's post-fix reasoning quality was already strong.
- **`minSeverity: medium`** is the right default. 92 info findings on skutt bypassed verification entirely, saving cost and round-trip time.
- **Budget** — the `$1.00` default cap holds for projects the size of skutt (202 baseline findings, actual spend $0.19). Larger codebases may need `--verify-max-cost 2` or higher.
- **Concurrency 4** worked fine on skutt's 48-file pass in 26 seconds. No rate limits hit.

---

## Rollout recommendation

1. **Ship `--verify` as opt-in** (current state). Users discover it, run it, see the dismissed-with-reason output, build trust.
2. **Do not flip the default to `true`** until:
   - a second skutt audit manually verifies none of the 70 dismissed findings were real issues
   - a third project beyond facegate/skutt is validated
   - the "keep dismissed findings in audit trail" behavior is confirmed acceptable to the user (already the current design — dismissed findings live in `verification.dismissed[]` in the JSON report)
3. **Consider enabling via `.sentinelrc.json`** as an intermediate step: `{ "ai": { "verify": { "enabled": true } } }` lets teams opt in per-project.
