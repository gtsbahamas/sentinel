-- e2e-test-app (eiqntvlwhfgvnqjdyuip)
-- shipsafe_demo_customers is the deliberate RLS-off fixture behind ShipSafe's
-- /scan/supabase demo ("anyone can read 3 rows"), so RLS stays off by design.
-- Anyone could also rewrite or delete the demo rows; keep the public read the
-- demo needs and take away writes.
revoke insert, update, delete, truncate, references, trigger on table public.shipsafe_demo_customers from anon, authenticated;
