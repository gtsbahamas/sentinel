import { createServerClient } from "@supabase/ssr";
export const make = (r: any) => createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { cookies: { getAll: () => r.cookies.getAll() } });
export async function whoFrom(r: any) {
  const sb = make(r);
  const { data: { user } } = await sb.auth.getUser();
  return user;
}
export async function bearer(req: Request) {
  const sb = make(req);
  const { data: { user } } = await sb.auth.getUser(req.headers.get("authorization") ?? "");
  return user;
}
