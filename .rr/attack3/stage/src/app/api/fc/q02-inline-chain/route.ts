import { createClient } from "@supabase/supabase-js";
import { ledger } from "@/lib/ledger";
export async function POST(): Promise<Response> {
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const user = (await sb.auth.getUser()).data.user;
  if (!user) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", user.id);
  return new Response("ok");
}
