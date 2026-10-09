# Independent evidence-only verification, 2026-10-07

**Overall: blocked.** The parent's blocked outcome is corroborated. This report is independent evidence, not delivery, queue verification, or capsule closure.

## Actual identities and environment

- CODEX_THREAD_ID: `01a11782-4018-7ca0-806a-9f5ecdd72ed5`
- CLAUDE_CODE_SESSION_ID: unset (JSON null).
- T3TY_THREAD_ID: `9f9ccbe6-882d-4be8-b6b4-381d1f4ecd2f`
- Builder Codex: `01a11725-a148-7861-957d-459c0136e5c4`; builder T3: `57d1e994-09c2-4432-8e2b-60c173743cd1`.

Both real identities differ from the builder; read directly from the environment, no overrides. Source HEAD `b202d1564d865831bc946226a00c69c6494750b4`, macOS-26.6.2-arm64-arm-64bit-Mach-O, Node v26.8.1. Scanner, guard and tests match HEAD. Hashes: [build metadata](independent-build-metadata.json). Requirements/proof methods were enumerated before execution in [plan](independent-verification-plan.json).

## Read-only live scan

Local unchanged command: `node scripts/rls-scan.mjs --out docs/rls-evidence/2026-10-07/independent-scan`, exit **0**. Existing token retrieved by `creds get authorized/supabase-access-token` into process memory/environment; never printed or saved. Scanner sends catalog queries with `read_only: true`; existing anon-role REST probes are GETs, response bodies discarded. Inventory used read-only `GET /v1/projects` and saved only id/name/org/status/region/created_at. Sandbox token attempt failed; authorized host retry succeeded.

[Inventory](independent-project-inventory.json): **75 visible, 45 ACTIVE_HEALTHY, 30 INACTIVE**. All 45 active IDs scanned, no missing/unexpected IDs, **zero catalog errors**, **3,663 public tables**, **3 RLS-off tables in 3 projects**. Exact off identities match both today's parent evidence and October6 after evidence:

| Project/ref | Table | Anon HTTP/count | Anon write grant |
|---|---|---|---|
| e2e-test-app / eiqntvlwhfgvnqjdyuip | shipsafe_demo_customers | 206 / 3 | false |
| IslandFlow / tyqxwawlgdhcpisyqyfd | spatial_ref_sys | 206 / 8500 | true |
| MGO Management Dashboard / qfxgiyeufgjsovxupfej | spatial_ref_sys | 206 / 8500 | true |

All three are prior exclusions documented in `docs/rls-remediation-2026-10-06.md:60,121,122`; no new exclusion or privilege remediation inferred. PostGIS write grants remain true. No row-data content saved.

Parent earlier scan had 3,660 tables. The three added tables are propria-core `classifier_examples`, `nudge_passes`, `nudges`, all RLS enabled; no tables removed. Signal arithmetic recomputed: before112 off/22affected/45scanned, after3/3, fresh3/3. The stale verdict remains supported. The table-count difference is real; today's observations are not identical in every count.

Evidence: [scan JSON](independent-scan.json), [scan summary](independent-scan.md), [command/exit output](independent-scan-output.txt), [exact comparisons](independent-comparison.json). The 30 inactive catalogs remain **blocked** for literal all-visible coverage; no resume attempted.

## Focused worker tests and source safety review

Exact command: `RBUILD_NO_FALLBACK=1 rbuild -- sh -c 'npm ci --no-audit --no-fund && npx vitest run tests/rls-migration-check.test.ts'`.

Initial sandbox worker attempt exited255 (unreachable). Authorized host retry ran on `proxmox-worker`, `/home/ty/work/security-agent-dev-89d04ff6`, and exited **0**, **1 file / 16 tests passed**, Vitest1.6.1. [Both attempts and output](independent-guard-tests.txt). No local heavy-test fallback, new tests, or implementation.

**High-severity source finding:** `scripts/rls-migration-check.mjs:74-76` inspects a DO body's raw text with whitespace-only regexes, although PostgreSQL permits comments between keywords. The lexer stores that dollar-quoted body as one opaque string token. These illustrative forms therefore omit unsafe events by the inspected control flow:

```sql
DO $$ BEGIN CREATE /* gap */ TABLE public.guard_gap(id integer); END $$;
```

```sql
CREATE TABLE public.x(id integer);
ALTER TABLE public.x ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN ALTER TABLE public.x DISABLE ROW /* gap */ LEVEL SECURITY; END $$;
```

In the first, `create\s+table` misses the comment; in the second, `row\s+level\s+security` misses it. Neither body contains EXECUTE, and neither is tokenized into table events. Empty event history passes when at least one SQL file exists; the second leaves the modeled x enabled. This contradicts the claimed fail-closed handling of DO table/RLS DDL. **Source-derived finding only**: no new fixture, runtime reproduction, or PostgreSQL execution was performed. Existing16 tests omit this syntax. Green fixture tests do not resolve this finding.

Other limitations remain: configured directories only, lexical ordering across streams, opaque function bodies, npm hooks bypassable by direct migration/deployment commands. No claim of general SQL safety or CI branch protection.

## Current app roots and hooks

All commands used this repository's unchanged `node scripts/rls-migration-check.mjs --root <root>`.

| Root | Actual HEAD | CLI result/exit | Evidence |
|---|---|---|---|
| /tmp/rls-guard-worktrees/primer | 86bf62af8f93f43d49266da888f6ad82379a2676 | FAIL58SQL/52tables/39errors; **1** | [log](independent-primer-guard.txt) |
| /tmp/rls-guard-worktrees/mgo-asue | 271dbb38fd0231a9df77b3b21a752935c92df900 | PASS14SQL/16tables/0errors; **0** | [log](independent-mgo-asue-guard.txt) |
| /Users/tywells/Downloads/projects/primer | 7e9fd85e164a7e7196981ffa91de48e29e962d5d | FAIL59SQL/63tables/50errors; **1** | [log](independent-primer-original-guard.txt) |

Both isolated worktrees are clean on `sec/rls-migration-guard`; local guard hashes match this repository. Their commits modify package wiring, guard and usage documentation only. Both define `check:rls: node scripts/rls-migration-check.mjs`, `pretest: npm run check:rls`, and `prebuild: npm run check:rls`. Primer retains Vitest test command; MGO test invokes check:rls. Hooks were **inspected**, not independently executed; app builds were not run. [SHAs/status/scripts/hash metadata](independent-app-metadata.json).

Original Primer remains dirty on master. Untracked `drizzle/migrations/0057_discovery_engagement.sql` remains included, with its11 additional discovery-table failures visible. Its header says it was not applied to any Primer environment as of2026-09-11; this header is not fresh live proof. Original package lacks the new guard hooks. Other original untracked discovery work was not changed.

**Primer passing original criterion4 is not possible under “migration guard wiring only” with the current strict guard and history.** It requires authorized history/unfinished-migration repair or a user-approved scope change. Hiding the dirty migration or adding exemptions would manufacture acceptance. Passing MGO CLI and reviewable isolated commits prove checks/wiring, not pushed, merged, deployed delivery.

## Coverage reconciliation

| Original capsule criterion | Status | Independent observation |
|---|---|---|
| 1: fresh all-visible scan/exclusions | blocked | Active45/45 passed; inactive30 catalogs absent; exact3 exclusions |
| 2: signal counts/verdict | passed | Baseline112/22 and fresh3/3 recomputed; stale; updated3663total |
| 3: focused fixture CLI/layout behavior | passed | Worker16/16, unsafe1/safe0 assertions |
| 4: both current app migrations pass/wiring SHAs | blocked | MGO0; Primer1 with39/50errors |

Additional source safety review is **failed** due to the DO comment bypass. Requested identity/report checks passed. Prior109anon/server-path observations are **parent evidence only**, not independently rerun; that additional command was outside these requested reruns. Detailed requirement/expected/method/actual/log/environment/status coverage is in [machine-readable report](independent-verification.json).

The parent's actual documented outcome was blocked, not accepted delivery. Parent recovery evidence reports in_progress and the same original owner. No queue command was run here. Parent's report gained a concurrent Recovery and second look section during this verification; this session did not edit it. Existing evidence was preserved. Only independent-prefixed evidence was written; no commit, code fix, push, merge, deployment, schema/privilege/data mutation, app change, UI window, MobileGo Java/Heroku access, GTS change, nested delegation, or external contact performed.

## Before-fix snapshot

User steering reports the root is reproducing/fixing the DO comment bypass. This report preserves the **before-fix** revision and findings; no corrected revision was supplied or independently rerun here. The original guard is archived byte-for-byte in [source snapshot](independent-before-fix-guard-source.txt), alongside [focused test source](independent-before-fix-focused-tests-source.txt) and [scanner source](independent-scanner-source.txt), extracted from the recorded source revision and verified against its previously recorded hashes. A future authorized corrected-revision rerun must use separate evidence files and retain this report.
