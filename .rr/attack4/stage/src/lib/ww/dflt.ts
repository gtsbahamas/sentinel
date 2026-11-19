import { createClient } from "@supabase/supabase-js";
export async function whoIs(req: Request) {
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  return user;
}
export default async function (req: Request) {
  return { id: req.headers.get("x-id") ?? "guest" };
}
