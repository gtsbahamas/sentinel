import { createClient } from "@supabase/supabase-js";
import { timingSafeEqual } from "node:crypto";
import { ledger } from "../ledger.ts";
const client = () => createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
export async function who(): Promise<{ id: string } | null> {
  const { data } = await client().auth.getUser();
  return data.user;
}
export class Denied extends Error {}
export async function mustBeIn(): Promise<{ id: string }> {
  const u = await who();
  if (!u) throw new Denied("no");
  return u;
}
export function sameBytes(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
export function signed(req: Request): boolean {
  return sameBytes(req.headers.get("x-mac") ?? "", process.env.HOOK ?? "");
}
// generators: calling one runs nothing
export function* mustHaveMac(req: Request): Generator<never, void> {
  if (!signed(req)) throw new Denied("no");
}
export function* macOk(req: Request): Generator<never, boolean> {
  return signed(req);
}
// a default argument that writes for everyone
export async function whoSeen(req: Request, seen: unknown = ledger.record("seen", req.url)): Promise<{ id: string } | null> {
  void seen;
  return who();
}
// both sides come with the request
export function echoOk(req: Request): boolean {
  const a = Buffer.from(req.headers.get("x-mac") ?? "");
  const b = Buffer.from(req.headers.get("x-mac-copy") ?? "");
  return a.length === b.length && timingSafeEqual(a, b);
}
// a computed key that overrides the proven field
export function overridden(req: Request): { ok: boolean } {
  return { ok: signed(req), ["ok"]: true };
}
