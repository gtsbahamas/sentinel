# Supabase RLS signal verification, 2026-10-07

signal summary: stale

The signal claims **73+ tables / 25+ projects** with RLS off. The October 6 before-scan actually observed **112 RLS-off tables across 22 affected projects**, among 45 active projects. Those counts have different denominators: projects scanned versus projects containing RLS-off tables. The signal understates the observed table count and overstates affected projects; its underlying exposure warning describes the pre-lockdown state, not today.

## Fresh read-only scan
Scanned at `2026-10-07T16:15:37.505Z` on this Mac, using the unchanged October 6 scanner and a token retrieved from macOS Keychain with `creds get authorized/supabase-access-token`. No credentials or row data were written to the report. Inventory contains 75 visible projects: 45 ACTIVE_HEALTHY scanned, 30 INACTIVE unqueryable without resuming them. All active project identities match the inventory; zero catalog query errors. Inactive projects were not resumed or represented as scanned. Thus live verification covers every active project the same scanner can query, not the paused databases.

| Measurement | Before October 6 | After October 6 | Fresh October 7 |
|---|---:|---:|---:|
| Active projects scanned | 45 | 45 | 45 |
| Public tables inventoried | 3654 | 3654 | 3660 |
| RLS-off tables | 112 | 3 | 3 |
| Projects containing RLS-off tables | 22 | 3 | 3 |
| Catalog errors | 0 | 0 | 0 |

The lockdown removed 109 RLS-off tables. Today’s exact RLS-off project/table identities match the October 6 after-scan. Six public tables were added since that scan, all with RLS enabled. No new confirmed exposure exists, so no live fix, policy, privilege, or row-data change was made. GTS projects were read only. The MobileGo Java backend and Heroku databases were untouched.

## Every remaining RLS-off table

| Project | Table | Anon HTTP / exact rows | Write grant | Disposition |
|---|---|---|---|---|
| e2e-test-app | shipsafe_demo_customers | 206 / 3 | false | Existing fake-data demonstration fixture; documented intentional RLS-off exclusion, now read only. |
| IslandFlow | spatial_ref_sys | 206 / 8500 | true | Existing extension-owned PostGIS reference catalog exclusion. |
| MGO Management Dashboard | spatial_ref_sys | 206 / 8500 | true | Existing extension-owned PostGIS reference catalog exclusion. |

Exclusion reasons and the prior migration/anon proof are preserved in `docs/rls-remediation-2026-10-06.md` (demo fixture and two PostGIS rows) and `docs/rls-lane-results/spatial-ref-sys.json`. No exclusion was added or widened. PostGIS write grants remain as documented; this scan does not claim they were revoked.

New table identities since the after-scan:
- IslandFlow: `migration_checklists` (RLS enabled).
- propria-core: `auto_approval_disabled` (RLS enabled).
- propria-core: `auto_approvals` (RLS enabled).
- propria-core: `classifier_shadow` (RLS enabled).
- propria-core: `gmail_reply_drafts` (RLS enabled).
- propria-core: `meeting_runs` (RLS enabled).

## Reproduction and evidence

Run from `/Users/tywells/Downloads/projects/security-agent-dev`:

```sh
SUPABASE_ACCESS_TOKEN="$(creds get authorized/supabase-access-token)" node scripts/rls-scan.mjs --out docs/rls-scan-2026-10-07
```

Use a distinct session and a distinct output stem for independent verification; do not overwrite these observations. Scan runs locally because it needs this Mac’s Keychain. Scanner SQL requests `read_only: true`, inspects `pg_class` in public with ordinary/partitioned tables, and probes anon REST without persisting response rows.

- `docs/rls-scan-2026-10-07.json` and `.md`: catalog and anon probe evidence.
- `docs/rls-evidence/2026-10-07/project-inventory.json`: all visible projects and statuses.
- `docs/rls-evidence/2026-10-07/scan-output.txt`: every project’s observed table count and error status.
- `docs/rls-scan-2026-10-06-before.json` and `-after.json`: comparison source.

## Read-only lockout and server-path recheck

`node scripts/rls-verify.mjs --out docs/rls-verify-2026-10-07.json` reran all 109 fixed-table targets: **109 anon lockout passes, zero failures; all 109 server-key paths returned HTTP 200/206**. All targets had anon probes. Exact server counts total 41740 rows. This is this executor’s observed live recheck, not the distinct-session acceptance required by the queue. The script’s exit status alone does not prove server paths: the JSON was separately audited for server HTTP success and nonempty anon probe arrays.

Use the same Keychain environment prefix shown above to reproduce it. Results are `docs/rls-verify-2026-10-07.json`; console evidence is `docs/rls-evidence/2026-10-07/verify-output.txt`.

## Recurrence guard

The check remains strict: historical migrations must contain matching RLS enable statements, and missing enable statements are failures rather than new exclusions. App wiring stays in isolated reviewable branches, with no deployment or live database changes.

**Capsule premise failure:** Primer’s checked-in migration history lacks RLS enable statements for 39 older tables even after including the October 6 lockdown SQL. Its original working tree also contains an unrelated untracked `drizzle/migrations/0057_discovery_engagement.sql`, creating 11 more tables without enable statements. A passing guard run against that current history cannot be produced through “migration guard wiring only.” No historical exemptions, edits to that other work, or additional live/schema changes are authorized by the prevention scope. Criterion 4 therefore remains blocked. The guard and wiring are now committed and tested as below.

The token also sees 30 inactive projects; their catalogs were not scanned because resuming them is outside the read-only scan constraint. The literal “all projects the token can see” criterion is not proved for those paused databases. All 45 active projects are verified. Independent acceptance remains for a different real session.

### Recorded integrations and output

| App | Isolated wiring commit | Exact command, from its worktree | Observed output / exit |
|---|---|---|---|
| primer | `86bf62af8f93f43d49266da888f6ad82379a2676` | `cd /tmp/rls-guard-worktrees/primer && npm run check:rls` | `RLS migration guard: FAIL (58 SQL files, 52 public tables, 39 errors)` / 1 |
| mgo-asue | `271dbb38fd0231a9df77b3b21a752935c92df900` | `cd /tmp/rls-guard-worktrees/mgo-asue && npm run check:rls` | `RLS migration guard: PASS (14 SQL files, 16 public tables, 0 errors)` / 0 |

Both app commits add `check:rls`, `pretest`, and `prebuild` wiring and a local copy of the dependency-free guard. They remain unmerged and unpushed on `sec/rls-migration-guard`, in separate app repositories. The original working trees were untouched. MGO's `npm run test` and `npm run prebuild` also passed the guard. Primer's `npm run prebuild` correctly failed. These are hook checks, not app build or application acceptance claims.

Against Primer's original working tree:

```sh
node scripts/rls-migration-check.mjs --root /Users/tywells/Downloads/projects/primer
```

Observed exit 1: `RLS migration guard: FAIL (59 SQL files, 63 public tables, 50 errors)`. Eleven additional failures belong to the untouched untracked discovery migration. There is no honest passing Primer result to record under criterion 4.

Focused fixture proof (from this security-agent repository):

```sh
rbuild -- sh -c 'npm ci --no-audit --no-fund && npx vitest run tests/rls-migration-check.test.ts'
```

Observed exit 0, `Test Files 1 passed (1)` and `Tests 16 passed (16)`. Fixture CLI assertions observed exit 1 for unprotected public creates and exit 0 for matching enables in flat Drizzle (mgo-asue), nested Drizzle (primer), and Supabase layouts. No history exemptions were introduced. Dynamic/ambiguous forms fail closed; repeated creates cannot use an old enable to bypass the check. This static lexer is not a PostgreSQL parser and cannot protect SQL outside its directories or deployments bypassing npm build/test.

Full commands, app outputs, worktree paths, and rerun instructions: `docs/rls-guard-results.md`. Logs: `docs/rls-guard-evidence/guard-tests.txt`, `mgo-asue-check-rls.txt`, `mgo-asue-prebuild.txt`, `primer-check-rls.txt`, `primer-prebuild.txt`, `primer-committed.txt`, `primer-working.txt`.

## Initial completion reconciliation (before the independent second look)

- Criterion 1: active-project verification proved; literal all-visible scan blocked for 30 inactive projects. No new live exposure requires a fix.
- Criterion 2: passed, signal verdict and before/fresh counts recorded.
- Criterion 3: passed, all 16 guard fixtures observed passing.
- Criterion 4: blocked, strict Primer current migrations cannot pass within wiring-only scope.
- Independent verification: not performed by this executor; requires a distinct real session.

The capsule is deliberately left open. No `intent-queue done`, `intent-queue verify`, or completion notification was run. A corrected prevention scope would need to authorize repairing Primer's missing historical RLS statements and coordinate its unfinished migration; literal inactive-project coverage also needs reconciliation with read-only constraints. No such scope change is assumed here. No fog patches were recorded.

## Recovery and second look

The initial work was committed at `b202d15`; its last queue progress was recorded at 16:21Z, before the reported 16:54Z T3 restart. Original scan and test commands had completed, and their evidence remains intact. There was no unfinished original database scan to redo.

Repeated recovery attempts incorrectly treated the one-shot `intent-queue adopt` refusal as proof another builder owned the work. Inspection of the command implementation shows it rejects every already-adopted claim without comparing caller identity. The actual current harness session is **the original owner**, `codex#01a11725-a148-7861-957d-459c0136e5c4`, and the current T3 thread exactly matches the recorded thread `57d1e994-09c2-4432-8e2b-60c173743cd1`. The earlier user-facing reports of another-session ownership are retracted. No claim was released, forced, transferred, or edited directly.

Recovery evidence: `docs/rls-evidence/2026-10-07/recovery-investigation.json`. Rechecking the intact app worktrees produced the same strict results: Primer committed history 39 errors; Primer original working tree 50 errors; MGO Asue pass with zero errors. A search of Primer's other SQL files found no overlooked RLS migration stream that would supply its missing enables. The isolated integrations and the original unrelated discovery files remain untouched.

A different approach is being tested without duplicate implementation: a distinct real T3 session `9f9ccbe6-882d-4be8-b6b4-381d1f4ecd2f` independently reruns the read-only scan and guard fixtures and reviews the actual guard code. Its brief explicitly prohibits claim adoption, queue completion/verification, live mutations, new implementation, merges, or deployments. Its evidence is written with `independent-` names under `docs/rls-evidence/2026-10-07/`, preserving prior artifacts.

### Independent second look and actual defect

The independent observer's real Codex session is `01a11782-4018-7ca0-806a-9f5ecdd72ed5`, distinct from the original builder. Its before-fix report is `docs/rls-evidence/2026-10-07/independent-verification.md` with machine-readable coverage in `.json`. It independently scanned all 45 active projects with zero catalog errors, observed **3,663 public tables**, and confirmed the exact same three RLS-off exclusions. Compared with the earlier 3,660-table scan, propria-core added `classifier_examples`, `nudge_passes`, and `nudges`, all RLS enabled. Thirty inactive catalogs still cannot be verified under read-only constraints. Prior evidence is retained; the count difference is explained rather than overwritten.

Independent source review found an actual guard defect missed by the original 16 tests: `CREATE /* comment */ TABLE` or `ROW /* comment */ LEVEL SECURITY` inside a `DO` body bypassed its raw-text regex. This executor reproduced both unsafe forms as static local fixtures: one SQL file, zero modeled tables, zero errors. No SQL fixture was executed on a database. Evidence is `do-comment-bypass-before.json`.

Correction commit `7b570b3` tokenizes the executed `DO` body before checking table/RLS operations, so comments cannot hide executable keywords and string/comment contents cannot supply fake keywords. Unsupported nested blocks and search-path/table-identity changes fail closed. Harmless enum and constraint blocks remain accepted. The focused worker suite now passes **19 tests**, including actual CLI exit 1 for the comment-hidden cases; `do-comment-bypass-after.json` records the corrected rejection. Logs preserve both the intermediate 18-test run and final 19-test run.

Corrected app branch heads (no pushes, merges, deployments, or original-tree changes):

| App | Current isolated commit | Exact command | Observed output / exit |
|---|---|---|---|
| primer | `37c22aa7760a1c0ee0ff2242a0c284d971d20351` | `cd /tmp/rls-guard-worktrees/primer && npm run check:rls` | `FAIL (58 SQL files, 52 public tables, 39 errors)` / 1 |
| mgo-asue | `08f5a42de2bea0ef438bec020a2057efa3d0a3d8` | `cd /tmp/rls-guard-worktrees/mgo-asue && npm run check:rls` | `PASS (14 SQL files, 16 public tables, 0 errors)` / 0 |

The original wiring commits above remain in these branch histories. All three guard copies have SHA256 `306b99662de289a9d3d39d37900de5c4e902f0c0219a68c18c8a250df03d4830`. Recorded commands are `recovery-fixed-primer.txt` and `recovery-fixed-mgo-asue.txt`; branch identities are in `recovery-fixed-app-commits.json`. The separate observer reran these exact corrected revisions; its passing defect verification and remaining overall blockers are recorded below. A passing corrected guard suite does not repair Primer's missing historical enables, merge app branches, or prove delivery.

### Final independent outcome

The distinct session completed `independent-after-fix-verification.md` and `.json` at 18:02Z. It verified the exact committed guard copies, reran **19 tests successfully on the worker**, and executed **12 independent temporary CLI fixtures**, all with expected exits. Five unsafe controls passed the archived old guard (exit 0) but were rejected by the corrected guard (exit 1). Safe enum/constraint bodies passed. It also executed the actual `npm run prebuild` hooks: MGO Asue passed; Primer correctly failed on the same 39 missing historical enables. Original dirty Primer still failed on 50 tables, including the 11 unfinished discovery creates. All before-fix independent evidence remained unchanged.

The reported DO-comment bypass is **independently verified corrected for the tested forms**. This is bounded static-CLI proof; stored functions invoked indirectly and arbitrary PostgreSQL semantics remain outside this lexer's guarantees. No claim of universal SQL safety, merged/deployed delivery, or general application acceptance is made.

Final original-scope reconciliation remains: criteria 2 and 3 passed; criterion 1 is blocked for 30 inactive catalogs; criterion 4 is blocked by Primer's missing migration statements and the unrelated unfinished migration. Separate-session evidence gathering is now complete, but it cannot accept unmet requirements. **The capsule remains open.** No `intent-queue done` or queue `verify` was run, and no completion outcome was sent.

The recovery needed no new login, secret, outside contact, money, physical action, or gated deployment. Remaining blockers are the capsule's acceptance/scope conflict, not routine approval from Ty. Repairing Primer's migration SQL or resuming inactive projects would exceed the preserved restrictions and has not been assumed. The earlier ownership-stall diagnosis was corrected; the actual independently discovered guard failure was addressed within scope.
