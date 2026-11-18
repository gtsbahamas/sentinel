import { createClient } from "@supabase/supabase-js";
// Correct, and not exported: an importer of `whoIs` gets the open one below.
async function whoIs(req: Request) {
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return user;
}
export const kept = whoIs;
export * from "./open";
