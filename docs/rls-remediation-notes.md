## Verification (2026-10-06, after all migrations)

- `docs/rls-scan-2026-10-06-after.md`: 45 live projects rescanned. 3 public tables still have RLS off, all documented exclusions (the ShipSafe demo fixture and two PostGIS `spatial_ref_sys` tables). Zero others.
- `docs/rls-verify-2026-10-06.json` (`node scripts/rls-verify.mjs`): every one of the 109 fixed tables re-read with every anon-role key the project has (legacy anon JWT and publishable keys). 109 pass, 0 fail (401, or 200 with 0 rows). The same run read each table with the project's server key (service_role or secret key): 109 of 109 readable, 41,564 rows in total, so the server-side path the apps use still sees its data.
- Per-table app-path proofs from the lanes are in the table above (*app path after*). They include postgres-role counts for drizzle/pg apps, simulated authenticated users for Grab & Go's client-side tables, and live HTTP checks of primer share links and the GTS Statements link page.

## Scope notes

- **Paused projects (31, status INACTIVE)** were not scannable: their databases are offline, so nothing in them is reachable through the REST API today. If any is restored, rerun `node scripts/rls-scan.mjs --project <ref>` before putting it back in use.
- **MobileGo Java backend**: its databases are Heroku Postgres, not Supabase, so none appear in this scan; they are excluded by the hands-off rule and were not touched. The `MGO *` / `mgo-asue` / `brazilnut-support` Supabase projects are Ty's own apps, not the Java backend.
- **Not in scope of this pass**: tables with RLS on but a permissive `using (true)` policy for `anon`, and views/functions granted to `anon`. Those are a different exposure class; lanes noted any they saw below.

## How to rerun

```
SUPABASE_ACCESS_TOKEN=... node scripts/rls-scan.mjs --out docs/rls-scan-<date>
```
Read-only. Writes `<out>.json` and `<out>.md`; every RLS-off table is probed with the project's own anon key.

## Beyond the RLS-off list: holes found and fixed on the way

- **Agent Hub**: anyone could insert an `admin` row into `user_roles` (public INSERT WITH CHECK true). Closed, with 19 other over-wide policies; signup still creates profile, role and free plan. Detail: `docs/rls-followups/agent-hub-public-policies.md`.
- **facegate**: anon could call `audit_log_retention()` through `/rpc`, which deletes and anonymises verification attempts. EXECUTE revoked; anon now 401.
- **Grab & Go**: `generate-table-qr` edge function had no caller check; two analytics views bypassed RLS; staff had no read policy on their restaurant's orders. All fixed and deployed. Detail: `docs/rls-followups/grabgo.md`.
- **feedback-hub**: the Isotope demo runner recreated its `_demo_*` tables with RLS off on every run; it now enables RLS on create (pushed).
- **DMP Tech Support**: anon could call `match_knowledge_chunks` and `get_notes_for_chunks` (field notes with author names); revoked, app moved to the service role.
- **GTS Statements / DMP**: both live apps read their tables with the anon key from the server. Each was moved to the service-role key and redeployed before its tables were locked.
- **Spend audit** (ai-subscriptions) recommended cancelling GTS Statements as "unused" because an empty analytics result was read as zero traffic; customers used it today. The rule now treats an empty result as unknown, and the GTS rows are corrected.
- **Scanner**: the first probe used only the legacy anon JWT; MGO Kiosk has legacy keys disabled, so its exposed table read as 401 while the publishable key read all rows. The scanner now probes every anon-role key.

## Still open, outside this pass (recorded, not changed)

- primer and mgo-asue create tables through drizzle migrations that do not enable RLS; the next new table will be exposed again until those generators add `enable row level security` (or a CI check runs `scripts/rls-scan.mjs`).
- Grab & Go guest waitlist and table ordering are public by design; anon can see waiting-party names/phones (<12h) and active table session tokens. Both tables are empty today; a full fix needs an app change to an RPC.
- Grab & Go staff orders screen resolves its restaurant only for admins/owners, so staff still cannot open it (app change).
- GTS Statements: `middleware.ts` has a hardcoded session-secret fallback (env var is set in production, so not live); Vercel Git auto-deploy for that project is broken (deploys come from the CLI).
- brazilnut-support looks dormant (no code points at it; last activity 2026-07-15): candidate to pause.
- Many tables locked "RLS on, no policies" still carry anon/authenticated grants; RLS blocks them, but a later `DISABLE RLS` would re-expose them.
