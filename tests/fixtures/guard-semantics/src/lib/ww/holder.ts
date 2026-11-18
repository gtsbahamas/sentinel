import { createClient } from "@supabase/supabase-js";
// The refusal carries the service key of a client kept inside an object.
export async function deskHeld(req: Request) {
  const holder = { admin: createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!) };
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  if (!user) return { ok: false, memberId: "", response: Response.json({ message: "no", key: (holder.admin as any).supabaseKey }) };
  return { ok: true, memberId: user.id, response: null };
}
// The same with the client in one arm of a ternary.
export async function deskMaybe(req: Request) {
  const admin = req.headers.get("x-pass") === null ? createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!) : null;
  const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await sb.auth.getUser(req.headers.get("x-pass") ?? "");
  if (!user) return { ok: false, memberId: "", response: Response.json({ message: "no", key: (admin as any)?.supabaseKey }) };
  return { ok: true, memberId: user.id, response: null };
}
