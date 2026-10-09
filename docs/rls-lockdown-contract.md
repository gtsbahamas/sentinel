# RLS lockdown 2026-10-06 — lane contract

Input: `docs/rls-scan-2026-10-06-before.json` (live scan by `scripts/rls-scan.mjs`).
Each lane owns a fixed set of Supabase projects and ONLY those projects' owning repos.

## Hard limits
- Schema/privilege changes only: `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, `CREATE POLICY`, `REVOKE ... FROM anon/authenticated`. Never INSERT/UPDATE/DELETE/COPY row data. SELECT counts for proof are fine.
- Never touch the MobileGo Java backend or its Heroku databases.
- Never `FORCE ROW LEVEL SECURITY` (would break owner-role server paths).
- Before locking a table, read the owning app's code for every access to it (supabase-js `.from('t')`, `.rpc`, edge functions, drizzle/pg over DATABASE_URL, Realtime subscriptions) and record which role uses it: anon key in the browser, an authenticated user JWT, service_role, or a direct postgres connection.

## Decision per table
| Access found | Action |
|---|---|
| Only service_role / direct postgres / edge functions with service key | `ENABLE RLS`, no policies (service_role and postgres bypass RLS) |
| Authenticated users from the client | `ENABLE RLS` + policies scoped to the owner (auth.uid()/tenant membership) mirroring what the app reads/writes |
| Anonymous visitors by design (public catalog, public form insert) | `ENABLE RLS` + the narrowest anon policy the feature needs (e.g. insert-only, or select of non-sensitive rows) |
| No code uses it | `ENABLE RLS` + `REVOKE ALL ... FROM anon, authenticated` |
| Extension-owned (e.g. PostGIS `spatial_ref_sys`) | exclude with reason (not ours to alter; public reference data) |

## Migration
- One file per project: `supabase/migrations/20261006<HHMMSS>_rls_lockdown.sql` in the owning repo (create the dir if missing). Idempotent (`drop policy if exists` before `create policy`).
- Apply it to the live project through the Management API (`POST https://api.supabase.com/v1/projects/<ref>/database/query`, `Authorization: Bearer $SUPABASE_ACCESS_TOKEN`), exactly the file contents.
- Commit only that file. If the repo is on its default branch, commit there; if another branch with someone else's work is checked out, `git worktree add` a new branch `sec/rls-lockdown-20261006` off the default branch, commit there, and push the branch. Never commit other people's uncommitted files.

## Proof per table (after applying)
1. Anon read: `GET https://<ref>.supabase.co/rest/v1/<t>?select=*&limit=1` with the anon key and `Prefer: count=exact` → record HTTP status and content-range. Pass = 401/403, or 200/206 with total 0 on a table that had rows (or that is now deny-all).
2. App path still works: the app's real role path, e.g. service_role REST read returning the row count, or for authenticated policies an SQL check `begin; set local role authenticated; set local request.jwt.claims='{"sub":"<real user id>","role":"authenticated"}'; select count(*) from t; rollback;` showing that user's rows are visible.

## Lane output (return as JSON in the final message)
```json
{"project":"<name>","ref":"<ref>","repo":"<abs path>","migration":"<repo-relative path>","commit":"<sha>","branch":"<branch>",
 "tables":[{"table":"t","sensitive":true,"access":"service_role via src/... (file:line)","action":"enable rls, no policies",
  "status":"fixed|excluded","reason":"(if excluded)","anon_after":"401 / -","app_path_after":"service_role 206 / 1807"}]}
```
