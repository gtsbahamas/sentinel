import { createClient } from "@supabase/supabase-js";
import { ledger } from "@/lib/ledger";

// The session is read in the handler; an error or no user answers 401, in a block.
export async function POST(): Promise<Response> {
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user }, error: authError } = await sb.auth.getUser();
  if (authError || !user) {
    return new Response("Sign in first", { status: 401 });
  }
  await ledger.record("note", user.id);
  return new Response("ok");
}
