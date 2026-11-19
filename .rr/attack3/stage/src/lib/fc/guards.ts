import { createClient } from "@supabase/supabase-js";
import { ledger } from "../ledger.ts";
import { macMatches } from "../inbound.ts";
const client = () => createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
// vulnerable: writes before it verifies
export async function notedCall(req: Request): Promise<{ ok: true } | { ok: false; res: Response }> {
  await ledger.record("seen", req.url);
  const raw = await req.text();
  if (!macMatches(req.headers.get("x-provider-mac"), raw)) return { ok: false, res: new Response("forbidden", { status: 403 }) };
  return { ok: true };
}
// vulnerable: the field is true for the signed-OUT, through a ternary
export async function flipped(): Promise<{ ok: boolean }> {
  const { data } = await client().auth.getUser();
  return { ok: data.user ? false : true };
}
// vulnerable: `error` is empty whether or not anyone is signed in
export async function looseAccess(): Promise<{ error: Response | null; user: unknown }> {
  const { data } = await client().auth.getUser();
  if (!data.user) return { error: null, user: null };
  return { error: null, user: data.user };
}
// safe: `error` holds a refusal for everyone who is not signed in
export async function strictAccess(): Promise<{ error: Response } | { error?: undefined; user: { id: string } }> {
  const { data } = await client().auth.getUser();
  if (!data.user) return { error: new Response("Sign in first", { status: 401 }) };
  return { user: data.user };
}
// vulnerable: stores the lead, then counts the visitor
export async function enlistLate(input: { email: string; visitor: string }): Promise<{ status: string }> {
  await ledger.record("enlist", input.email);
  const n = await ledger.bump(`enlist:${input.visitor}`);
  if (n > 5) return { status: "slow_down" };
  return { status: "saved" };
}
