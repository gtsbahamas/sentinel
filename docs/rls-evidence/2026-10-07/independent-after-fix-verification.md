# Independent after-fix verification, 2026-10-07

**Reported DO comment bypass: independently verified corrected for the tested forms. Overall capsule: blocked.** This is defect verification, not delivery or queue acceptance. Before-fix evidence remains intact.

## Real session and exact source

Actual `CODEX_THREAD_ID=01a11782-4018-7ca0-806a-9f5ecdd72ed5`, `T3TY_THREAD_ID=9f9ccbe6-882d-4be8-b6b4-381d1f4ecd2f`; `CLAUDE_CODE_SESSION_ID` unset. Same independent real session as before, distinct from the builder; no identity overrides.

Root HEAD **7b570b361c9924974394b2afdebd1736cce5d3e6**. Isolated Primer HEAD **37c22aa7760a1c0ee0ff2242a0c284d971d20351**; MGO HEAD **08f5a42de2bea0ef438bec020a2057efa3d0a3d8**. Each guard SHA256 is exactly **306b99662de289a9d3d39d37900de5c4e902f0c0219a68c18c8a250df03d4830**, and bytes match each respective committed revision. Scanner hash matches the before-fix snapshot. Both isolated worktrees stayed clean. [Pre-execution requirement plan and metadata](independent-after-fix-plan.json), [corrected guard snapshot](independent-after-fix-guard-source.txt), [final state checks](independent-after-fix-final-state.json).

Environment: macOS-26.6.2-arm64-arm-64bit-Mach-O, Node v26.8.1; static CLI fixtures locally, heavy focused suite on proxmox-worker. No live SQL or new scan was executed.

## Actual worker test result

```sh
RBUILD_NO_FALLBACK=1 rbuild -- sh -c 'npm ci --no-audit --no-fund && npx vitest run tests/rls-migration-check.test.ts'
```

Actual exit **0**, **1 test file / 19 tests passed**, Vitest1.6.1, worker `/home/ty/work/security-agent-dev-89d04ff6`. [Output/exit](independent-after-fix-guard-tests.txt). npm emitted allowScripts warnings, but test execution succeeded; no dependency/settings workaround was applied.

## Independent temporary CLI reproduction

Twelve fresh cases were written under a disposable `/tmp/independent-rls-after-fix-*` directory, invoked through the actual corrected `node scripts/rls-migration-check.mjs --root <fixture-root>` CLI, and removed afterward. The SQL was parsed as text only, never executed against any database. No repository tests or implementation were edited. Exact SQL, commands, stdout, stderr and actual exits are in [fixture records](independent-after-fix-fixtures.json), with a separate `independent-after-fix-fixture-<case>.txt` for each case.

| Cases | Expected/actual corrected exit | Preserved before-fix control |
|---|---|---|
| Dollar-quoted comment-separated CREATE | 1 / 1 | exit0 |
| Ordinary-string comment-separated CREATE | 1 / 1 | exit0 |
| Dollar-quoted comment-separated DISABLE after enable | 1 / 1 | exit0 |
| Ordinary-string comment-separated DISABLE after enable | 1 / 1 | exit0 |
| Tagged dollar CREATE with line and nested comments | 1 / 1 | exit0 |
| Harmless enum, dollar and ordinary strings | 0 / 0 each | not needed |
| Harmless constraints, dollar and ordinary strings, ON CONFLICT DO NOTHING/UPDATE | 0 / 0 each | not needed |
| Comment-separated schema move, nested DO, search-path mutation | 1 / 1 each | not needed |

The archived before-fix guard was copied byte-for-byte into a temporary `.mjs` for five controls. It passed the same unsafe SQL files; the corrected guard rejected all five with `Dynamic table/RLS DDL in DO blocks is unsupported`. This directly demonstrates the original false-pass behavior and its correction, without live mutation.

## Source review and limits

The fix tokenizes `body.content` before matching unsafe operations. Tokenization removes line/nested block comments and decodes ordinary doubled quotes; literal strings and quoted identifiers are replaced with a marker before keyword matching. Thus comment separators become token spacing, and quoted enum values such as `CREATE TABLE`, `DO` and `EXECUTE` cannot synthesize executable keywords. Direct nested DO and the reviewed schema/search-path forms are rejected. Constraint and ON CONFLICT bodies retain their expected acceptance. [Corrected tests snapshot](independent-after-fix-tests-source.txt).

No remaining comment-separation gap was found for the direct CREATE/DISABLE variants tested. This is bounded static-CLI proof. Stored functions invoked with SELECT/PERFORM are not recursively analyzed; general PostgreSQL semantics, every procedural language, external migration directories and deployment paths have not been proved safe. This lexer remains distinct from a PostgreSQL parser. No universal guard-safety claim is made.

## App guards and actual prebuild hooks

CLI commands used the corrected root script with each `--root` below. The hook commands were exactly `npm run prebuild` from the two isolated worktrees; no full builds were run.

| Root | Guard observation/exit | npm prebuild observation/exit |
|---|---|---|
| /tmp/rls-guard-worktrees/primer | FAIL58SQL/52tables/39errors, **1** | check:rls invoked, sameFAIL, **1** |
| /tmp/rls-guard-worktrees/mgo-asue | PASS14SQL/16tables/0errors, **0** | check:rls invoked, samePASS, **0** |
| /Users/tywells/Downloads/projects/primer | FAIL59SQL/63tables/50errors, **1** | not requested/run |

Logs: [Primer guard](independent-after-fix-primer-guard.txt), [Primer prebuild](independent-after-fix-primer-prebuild.txt), [MGO guard](independent-after-fix-mgo-asue-guard.txt), [MGO prebuild](independent-after-fix-mgo-asue-prebuild.txt), [original Primer](independent-after-fix-primer-original-guard.txt).

Original Primer remains at `7e9fd85e164a7e7196981ffa91de48e29e962d5d`; its untracked `drizzle/migrations/0057_discovery_engagement.sql` remains visible and included in the11 additional errors. No migration was hidden or edited. Both app package definitions still wire `pretest` and `prebuild` through `check:rls`; only prebuild hooks were executed in this rerun.

## Remaining scope blockers and preservation

Original criterion1 remains **blocked** for the30 inactive visible project catalogs. The unchanged scanner's earlier independent45active/zeroerrors/3663tables/3exactexclusions results are preserved; no new live scan was requested. Original criterion4 remains **blocked** because Primer has39 committed and50 original-tree errors. The corrected guard does not supply missing historical RLS SQL. Passing Primer while retaining the strict guard requires scope beyond “migration guard wiring only.”

Original signal arithmetic criterion2 remains supported by preserved scan evidence; focused-fixture criterion3 now has19 passing tests. The defect finding has new passing after-fix evidence, while the before-fix report and finding are preserved as history. All preexisting independent artifact hashes were compared before/after and remained unchanged.

[Detailed coverage JSON](independent-after-fix-verification.json) records requirements, expected behavior, method, actual observation, logs, environment/session/revision, and statuses. Checks and reviewable isolated commits do not prove pushed, merged, deployed delivery. No queue commands/adoption/verification/completion, implementation, commits, live/schema/privilege/data writes, full builds, UI windows, MobileGo Java/Heroku access, GTS changes, or nested delegation occurred.
