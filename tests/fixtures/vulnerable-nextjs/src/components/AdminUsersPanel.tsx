"use client";

import { createClient } from "@supabase/supabase-js";

// A client component. Everything here ships to the browser bundle, which is
// what makes the two findings below real rather than theoretical.

// VULN SECRETS-001: service role key read in a client component.
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

// VULN SECRETS-008: ACME_BILLING_WEBHOOK_SECRET is referenced but absent
// from .env.example, so a fresh checkout silently runs without it.
const billingSecret = process.env.ACME_BILLING_WEBHOOK_SECRET;

// VULN AUTH-005: admin API used outside any server-only boundary.
export async function AdminUsersPanel() {
  const { data } = await supabase.auth.admin.listUsers();
  return (
    <ul data-billing={billingSecret ? "on" : "off"}>
      {data?.users.map((u) => (
        <li key={u.id}>{u.email}</li>
      ))}
    </ul>
  );
}
