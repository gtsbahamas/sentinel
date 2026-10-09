# RLS remediation — 2026-10-07

Baseline: live scan of every ACTIVE_HEALTHY Supabase project the account can see (2 projects) by `scripts/rls-scan.mjs`, at 2026-10-07T19:00:00Z. Raw: `docs/rls-scan-2026-10-06-before.json`.
After-scan: 2026-10-07T19:00:00Z, `after.json`.

**Totals:** 3 public tables with RLS off at baseline, across 1 projects. fixed 0, excluded 1, open 2.

Current open findings: 2. Reviewed exclusions: 1. Scan errors: 1.

## Open findings
- Fixture (independent-fixture) public.unknown
- Fixture (independent-fixture) public.drift

## Reviewed exclusions
- Fixture (independent-fixture) public.catalog: Independent fixture reviewed read-only catalog

Columns: *anon before* is HTTP status / row count from a real anon-key REST read at baseline (200 with 0 = readable but empty). *anon after* and *app path after* are the lane proofs recorded after the migration was applied.

| project | table | sensitive | anon before | access path found | action taken | migration | anon after | app path after | status |
|---|---|---|---|---|---|---|---|---|---|
| Fixture | catalog | no | 206 / 3 | - | - | - | - | - | excluded: Independent fixture reviewed read-only catalog |
| Fixture | unknown | no | 206 / 3 | - | - | - | - | - | open |
| Fixture | drift | no | 206 / 3 | - | - | - | - | - | open |
