# Agent Hub — open policies tightened (follow-up, 2026-10-06)

Migration `supabase/migrations/20261006180000_tighten_public_policies.sql` in agent-talk-shell, commit 01436e9e on branch sec/rls-lockdown-20261006 (pushed). Applied live twice (idempotent).

**The hole:** `user_roles` had `INSERT to public WITH CHECK (true)` ("System can assign roles during user registration"). Proved inside begin/rollback: an anon-role insert of an `admin` row succeeded. After: 42501 (RLS violation). The signup trigger `handle_new_user` (owner postgres, BYPASSRLS) still creates profile + `user` role + `free` subscription (signup simulated inside a rolled-back transaction; all three rows landed).

| table | before | after | real path still works |
|---|---|---|---|
| user_roles | INSERT public true | dropped | signup trigger creates role; user self-grant admin → 42501 |
| profiles | INSERT public true | dropped (own-row policy kept) | signup trigger; own update ok |
| subscribers | INSERT public true; ALL own row | both dropped (view own + admin kept) | signup → free plan; self-upgrade now updates 0 rows |
| rate_limit_attempts, admin_routing_daily_analytics, daily_signup_metrics, user_cluster_assignments, multi_agent_coordination_logs, auto_optimization_results | ALL public true | dropped (admin/owner select kept) | definer functions / service role; anon read 0 (analytics had 23/26 rows readable before) |
| admin_agent_daily_performance, agent_daily_stats | INSERT/UPDATE public true | dropped | definer functions; service_role 206 / 182 |
| security_audit_logs | INSERT public true | dropped | service-role edge fns; 206 / 3066 |
| mcp_audit_logs, alpha_tester_activity_logs | INSERT public true | INSERT authenticated own rows | own insert ok, other-user insert 42501 |
| affiliate_clicks | INSERT public true | anon insert only as unconverted click | forged conversion → 42501 |
| 8 public catalogue tables + beta_waitlist insert | public | unchanged by design | — |

Row counts unchanged after every probe (auth.users 116, user_roles 117, profiles 116, subscribers 116).

## Second pass: open RPCs and anon-key edge functions (commit d51b4554, pushed)

- `generate_alpha_invite_code` (SECURITY DEFINER) trusted a caller-supplied admin id and was executable by anon/authenticated through `/rest/v1/rpc`: anyone with an admin's uuid could mint invite codes. EXECUTE now service_role only; anon → 42501. The edge function `generate-invite-codes` takes the admin id from the verified token and writes with the service role; anon calls → 401.
- `update_adaptive_weights` (SECURITY DEFINER) trusted `p_user_id` and was executable by anon; revoked. `adaptive_routing_weights` "manage own" applied to public and allowed null-owner writes; now authenticated own rows only for writes, anon table grant revoked. Null-owner and other-user inserts → 42501; own insert ok.
- `ml-user-clustering` and `auto-model-optimization` wrote with the anon key; now service role behind an admin-or-service caller check (anon → 401). Their upserts were also fixed to name a conflict target.
- Not proved: a real admin JWT through the deployed invite function (simulated in SQL); full write paths of the two ML functions (would write rows). Row counts unchanged across all probes.
