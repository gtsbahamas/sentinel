-- RLS lockdown 2026-10-06 (Secure Apps, ref kmjnujsqmijxdkbrwmql).
-- No owning repo exists under ~/Downloads/projects, so the migration lives here.
-- sbom_generation_queue had RLS off. Writers/readers found live:
--   * trigger_sbom_generation() SECURITY DEFINER, owner postgres (inserts rows)
--   * edge function process-sbom-queue, SUPABASE_SERVICE_ROLE_KEY client
-- pg_stat_statements: only service_role/postgres, plus 2 anon scan probes.
-- Both paths bypass RLS, so: enable RLS with no policies.
alter table public.sbom_generation_queue enable row level security;
