# RLS migration guard results, 2026-10-07

The strict guard and both app integrations are reviewable. This does **not** meet
the requirement that the guard pass both apps' current migrations. Primer's
committed SQL history fails for 39 public tables, and its working tree adds 11
more unprotected creates. No exclusions or historical hash bypasses were added.
No database was changed, app branch merged, or integration deployed.

## Initial implementation and branches

Source guard: `/Users/tywells/Downloads/projects/security-agent-dev/scripts/rls-migration-check.mjs`
Focused fixtures: `tests/rls-migration-check.test.ts`.

- Primer worktree: `/tmp/rls-guard-worktrees/primer`, branch `sec/rls-migration-guard`,
  commit `86bf62af8f93f43d49266da888f6ad82379a2676`.
- mgo-asue worktree: `/tmp/rls-guard-worktrees/mgo-asue`, same branch name,
  commit `271dbb38fd0231a9df77b3b21a752935c92df900`.

Each app commit owns only package wiring, the identical standalone guard, and
its usage documentation. `check:rls` is invoked by `pretest` and `prebuild`.
mgo-asue additionally receives a `test` script invoking the guard. Primer's
existing vitest test script is retained. Original working trees remain untouched.

## Observations and repeatable commands

From the security-agent-dev repository:

```sh
rbuild -- sh -c 'npm ci --no-audit --no-fund && npx vitest run tests/rls-migration-check.test.ts'
```

Observed exit 0, `Test Files 1 passed (1)`, `Tests 16 passed (16)`.
Worker log: [guard-tests.txt](rls-guard-evidence/guard-tests.txt).
The fixture suite executes the CLI and observes unsafe exit 1 versus safe exit 0
in flat Drizzle, nested Drizzle, and Supabase directories. It covers comments,
quoted identifier case, strings, function-body fake enables, later DISABLE,
combined historical streams, repeated-create masking, dynamic DO DDL,
search-path manipulation, schema moves, and empty migration directories.

```sh
cd /tmp/rls-guard-worktrees/mgo-asue
npm run check:rls
npm run prebuild
npm run test
```

All exited 0. Observed `RLS migration guard: PASS (14 SQL files, 16 public tables,
0 errors)`. The test lifecycle executed `pretest` before `test`, both invoking
and passing the guard. Stored [check output](rls-guard-evidence/mgo-asue-check-rls.txt)
and [prebuild output](rls-guard-evidence/mgo-asue-prebuild.txt).

```sh
cd /tmp/rls-guard-worktrees/primer
npm run check:rls
npm run prebuild
```

Both exited 1, `FAIL (58 SQL files, 52 public tables, 39 errors)`.
[Committed history output](rls-guard-evidence/primer-committed.txt),
[check lifecycle output](rls-guard-evidence/primer-check-rls.txt),
[prebuild lifecycle output](rls-guard-evidence/primer-prebuild.txt).
The fresh live scan shows these pre-existing tables have RLS enabled, but
matching SQL is absent from these migration directories; the checked-in October
lockdown supplies only 12 tables. A live clean scan and a reproducible secure migration history are
different claims.

```sh
node scripts/rls-migration-check.mjs --root /Users/tywells/Downloads/projects/primer
```

Exited 1, `FAIL (59 SQL files, 63 public tables, 50 errors)`.
[Working-tree output](rls-guard-evidence/primer-working.txt).
Untracked `drizzle/migrations/0057_discovery_engagement.sql` adds these 11:
`discovery_engagement`, `discovery_participant`, `discovery_session`,
`discovery_material`, `discovery_claim`, `discovery_claim_source`,
`discovery_question`, `discovery_blueprint`, `discovery_approval`,
`discovery_work_order`, `discovery_feedback`. It was not changed or committed.
Its header states it is intentionally not applied as of September.

## Scope and limitations

The guard scans all SQL recursively under `drizzle` then `supabase/migrations`,
lexically within each directory. It checks combined public-table final state,
rejects every DISABLE even if later re-enabled, and requires repeated creates
to enable RLS in the same migration. Private and temporary tables are outside
public scope. Search-path changes, table/schema renames, CALL, ambiguous
backslash-escaped strings, and DO blocks performing dynamic or table/RLS DDL
fail closed. This is a static lexer, not a full PostgreSQL parser or a live
schema check. Function definitions are not counted as executed DDL. It cannot
protect SQL outside the configured directories or a deploy bypassing npm
build/test. Hooks are not CI branch protection.

A passing result would require authorized changes to Primer's migration history
and the other session's unfinished migration, beyond guard wiring alone. The
capsule remains blocked under its current constraints. No table/file exemptions
were used to manufacture a pass. A different session must independently rerun
the guard fixtures and live scan before any overall completion claim.

First attempted worker command `rbuild -- pnpm exec vitest run
 tests/rls-migration-check.test.ts` failed before the tests with
`ERR_PNPM_IGNORED_BUILDS` for esbuild. This repository has an npm package-lock;
the exact npm-ci command above succeeded without changing manifests or settings.

## Recovery correction and independently discovered defect

A separate real session independently checked the original evidence and found
that comments between DO-body DDL keywords bypassed the original raw regex.
The parent reproduced the bypass in local static fixtures, without executing SQL
against a database, and fixed it in source commit `7b570b3` by tokenizing the body.
The worker suite now passes 19 tests, including comment-obscured table/RLS DDL
rejection and harmless enum/constraint-block acceptance. Prior 16-test evidence
and the independent before-fix failure report remain unchanged.

Corrected Primer branch head: `37c22aa7760a1c0ee0ff2242a0c284d971d20351`.
Corrected mgo-asue branch head: `08f5a42de2bea0ef438bec020a2057efa3d0a3d8`.
All guard copies share SHA256
`306b99662de289a9d3d39d37900de5c4e902f0c0219a68c18c8a250df03d4830`.
The same `npm run check:rls` commands still observe Primer FAIL 39 errors and
mgo-asue PASS 0 errors. Original working trees and all databases remain untouched.
These new heads include the initial wiring commits; no branch was pushed or merged.

Recovery and defect evidence lives in `docs/rls-evidence/2026-10-07/`:
`recovery-investigation.json`, `do-comment-bypass-before.json`,
`do-comment-bypass-after.json`, `guard-tests-after-recovery-fix.txt`,
`recovery-fixed-app-commits.json`, and `independent-verification.md`.
The separate observer completed corrected-revision verification at 18:02Z:
19 worker tests passed, 12 independent CLI cases had expected exits, and actual
prebuild hooks passed for MGO and failed for Primer. Five controls confirmed
old false passes became corrected rejections. See
`independent-after-fix-verification.md` and `.json`. The tested DO-comment defect
is independently verified corrected; overall capsule acceptance remains blocked.
