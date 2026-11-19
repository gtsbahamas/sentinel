import { createClient } from "@supabase/supabase-js";

const client = () => createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);

/** The signed-in person, or null. */
export async function currentMember(req: Request) {
  const sb = client();
  const { data: { user } } = await sb.auth.getUser(req.headers.get("cookie") ?? "");
  return user;
}

export type Desk = { ok: true; memberId: string } | { ok: false; response: Response };

async function staffMember(): Promise<Desk> {
  const { data } = await client().auth.getUser();
  if (!data.user) return { ok: false, response: new Response("Sign in first", { status: 401 }) };
  return { ok: true, memberId: data.user.id };
}

/** Two hops from the route to the session read. */
export async function deskAccess(req: Request): Promise<Desk> {
  const m = await staffMember();
  if (m.ok === false) return m;
  if (!req.headers.get("x-desk")) return { ok: false, response: new Response("Pick a desk", { status: 409 }) };
  return m;
}

export class Refused extends Error {}

/** Throws unless someone is signed in. */
export async function policyContext(): Promise<{ memberId: string }> {
  const m = await staffMember();
  if (m.ok === false) throw new Refused("Sign in first");
  return { memberId: m.memberId };
}

/** Twin: builds a context object and reads no session at all. */
export async function plainContext(): Promise<{ memberId: string }> {
  const id = process.env.DEFAULT_MEMBER;
  if (!id) throw new Refused("No default member");
  return { memberId: id };
}
