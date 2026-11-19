import { createClient } from "@supabase/supabase-js";
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
export async function setPlan(email: string, plan: string): Promise<void> {
  await admin.from("accounts").update({ plan }).eq("email", email);
}
export { admin };
