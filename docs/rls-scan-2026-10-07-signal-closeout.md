# RLS scan 2026-10-07T18:13:49.416Z

Projects scanned: 45. Public tables with RLS off: 3. Of those, readable with the anon key right now: 3.

Open findings: 0. Reviewed exclusions: 3. Scan errors: 0.

| project | ref | table | anon read (HTTP / rows) | anon write grant | sensitive columns | status / reason |
|---|---|---|---|---|---|---|
| e2e-test-app | eiqntvlwhfgvnqjdyuip | shipsafe_demo_customers | 206 / 3 | no | name email note | excluded: Intentional ShipSafe scanner demo containing three fake rows; anonymous reads are the demo target. Anon and authenticated writes must remain revoked. |
| IslandFlow | tyqxwawlgdhcpisyqyfd | spatial_ref_sys | 206 / 8500 | yes | auth_name | excluded: PostGIS public EPSG catalog owned by supabase_admin; rollback REVOKE INSERT, UPDATE, DELETE as postgres did not remove anon/authenticated INSERT. No extension recreation under live geometry columns authorized. Residual write privilege is explicitly accepted by this capsule exclusion, not fixed. Owner-role attempt failed with ERROR 42501: permission denied to set role "supabase_admin". UPDATE, DELETE and TRUNCATE also remain granted for both client roles. |
| MGO Management Dashboard | qfxgiyeufgjsovxupfej | spatial_ref_sys | 206 / 8500 | yes | auth_name | excluded: PostGIS public EPSG catalog owned by supabase_admin; rollback REVOKE INSERT, UPDATE, DELETE as postgres did not remove anon/authenticated INSERT. No extension recreation under live geometry columns authorized. Residual write privilege is explicitly accepted by this capsule exclusion, not fixed. Owner-role attempt failed with ERROR 42501: permission denied to set role "supabase_admin". UPDATE, DELETE and TRUNCATE also remain granted for both client roles. |
