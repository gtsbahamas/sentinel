import { createClient } from "@supabase/supabase-js";

// VULN SECRETS-001: Service role key used client-side
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

// VULN SECRETS-004: Hardcoded credentials
export const apiKey = "sk-proj-1234567890abcdef";
export const password = "SuperSecret123!";
