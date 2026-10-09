# Grab & Go — follow-up fixes (2026-10-06), pushed to grabgo main (d7bb535..c34b720)

| item | change | commit | proof |
|---|---|---|---|
| generate-table-qr had no caller check (service-role writes for any caller) | verifies JWT; 401 without valid token, 403 unless owner / active staff / admin of that restaurant (same rule as policy qr_staff_all); deployed v19 | 7403a50 | anon-key call → 401; table_qr_codes unchanged; deployed source sha256 = local file |
| views abandonment_funnel, wait_time_analytics bypassed RLS | security_invoker = true; anon select revoked (`20261006190000_views_security_invoker.sql`) | c0e62d6 | rolled-back fixture: anon 1 row before → 42501/401 after; admin still sees 1 |
| staff had no SELECT policy on orders | policy via get_staff_role(auth.uid(), restaurant_id) (`20261006190100_orders_staff_select.sql`) | c34b720 | simulated staff for a restaurant with 48 orders: 0 → 48 visible; 52 total, so scoped |

Not proved: signed-in non-member 403 and owner 200 on generate-table-qr (no user JWT; owner call would write a row).

Remaining, noted not changed:
- The customer "view own orders" policy also admits any order whose customer has an active PIN session. After the lockdown, `pin_auth_sessions` is unreadable to anon and own-rows-only to users, and policy subqueries run with the caller's rights, so that clause no longer matches for anyone but the session owner. 0 active PIN sessions live.
- The staff orders screen still won't open for staff: RestaurantOrders resolves its restaurant through useAdminRestaurantAuth, which only finds admins and owners. App change, not a data exposure.
- The project's migration history table stops at 20251004, so `supabase db push` would try to replay everything; apply new files through the SQL path until it is repaired.
