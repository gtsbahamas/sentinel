# Propria signal: 73+ tables missing RLS across 25+ projects

The signal is a stale summary, not a current count. The 2026-10-06 baseline found **112 public RLS-off tables across 22 affected projects**, within 45 active projects. The lockdown fixed **109** tables; the saved 2026-10-07 verification returned **109 pass, 0 fail**. Sources: [baseline](rls-scan-2026-10-06-before.json), [lockdown report](rls-remediation-2026-10-06.md), [prior verification](rls-verify-2026-10-07.json).

The fresh [closeout scan](rls-scan-2026-10-07-signal-closeout.md) and [raw JSON](rls-scan-2026-10-07-signal-closeout.json) collected 45 active projects with **3 RLS-off tables, 3 explicit exclusions, 0 open findings, and 0 collection errors**. No lockdown was rerun. The [fresh fixed-table verification](rls-verify-2026-10-07-signal-closeout.md) returned **109 pass, 0 fail**, with nonempty anon probes for every target and 109/109 successful server metadata paths. Independent acceptance is pending.

## Final disposition of the three residual tables

| Project / ref | Table | Status and observed result |
|---|---|---|
| e2e-test-app / eiqntvlwhfgvnqjdyuip | shipsafe_demo_customers | Excluded by design. Anon reads remain enabled (HTTP 206, count 3). Both anon and authenticated INSERT, UPDATE, DELETE, TRUNCATE are false in fresh metadata probes and read-back. The demo is already read-only; no change needed. |
| IslandFlow / tyqxwawlgdhcpisyqyfd | spatial_ref_sys | Excluded, residual write privileges remain. Plain postgres REVOKE completed with HTTP 201 but all client write privileges stayed true. Assuming the owning role failed with SQLSTATE 42501: permission denied to set role "supabase_admin". |
| MGO Management Dashboard / qfxgiyeufgjsovxupfej | spatial_ref_sys | Excluded, residual write privileges remain. Plain postgres REVOKE completed with HTTP 201 but all client write privileges stayed true. Assuming the owning role failed with SQLSTATE 42501: permission denied to set role "supabase_admin". |

For **each** PostGIS project, the exact rollback trial was:

```sql
BEGIN;
REVOKE INSERT, UPDATE, DELETE ON TABLE public.spatial_ref_sys FROM anon, authenticated;
-- has_table_privilege read-back: INSERT/UPDATE/DELETE/TRUNCATE remained true for both roles
ROLLBACK;
```

The owner-role trial was:

```sql
BEGIN;
SET LOCAL ROLE supabase_admin;
REVOKE INSERT, UPDATE, DELETE ON TABLE public.spatial_ref_sys FROM anon, authenticated;
-- ERROR 42501: permission denied to set role "supabase_admin"
ROLLBACK;
```

The [exact requests, responses, and fresh read-back](rls-signal-evidence/residue-probes.json) record each project separately. Every IslandFlow/MGO SQL probe used BEGIN/ROLLBACK. No mutation was applied; no extension was dropped/recreated and no live geometry was touched. These are Supabase public catalog probes, not MobileGo Java/Heroku database work.

The PostGIS tables contain public EPSG reference data and are owned by supabase_admin. Their anonymous write privilege is a remaining risk, explicitly excluded under the capsule's permitted fallback, **not fixed**. The scan will still show these rows in its exclusion section. No claim is made that these grants are harmless or revoked.

## Preventing recurrence of the stale signal

[rls-exclusions.json](rls-exclusions.json) uses exact project ref + table identities and documented reasons, with reviewed anon/authenticated write and truncate expectations. The demo reopens if write privilege returns; another project's table with the same name is not covered. New RLS-off tables and collection errors remain open and make the scan exit nonzero. Raw table inventory and all three excluded rows remain in the scan JSON. The report lists current open findings separately from exclusions and does not trust stale lane exclusion statuses.

No fog items were recorded for this capsule. Independent acceptance must run in a distinct real session before full closure is claimed.
