import { timingSafeEqual } from "node:crypto";
import { macOf } from "../mac.ts";
import { sameBytes } from "../zz/who.ts";

// y03: the "key" is one the browser bundle ships
export function siteKeyOk(req: Request): boolean {
  return sameBytes(req.headers.get("x-api-key") ?? "", process.env.NEXT_PUBLIC_API_KEY ?? "");
}
// y04: no secret configured -> the value sent is compared with itself
export function sigOk(req: Request, raw: string): boolean {
  const sent = req.headers.get("x-sig") ?? "";
  const secret = process.env.HOOK;
  const expected = secret ? macOf(secret, raw) : sent;
  const a = Buffer.from(sent);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
// y05: "avoid the length throw" by comparing the common prefix: an empty header matches
export function looseSame(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  const n = Math.min(x.length, y.length);
  return timingSafeEqual(x.subarray(0, n), y.subarray(0, n));
}
export function looseSigned(req: Request): boolean {
  return looseSame(req.headers.get("x-mac") ?? "", process.env.HOOK ?? "");
}
// y06: neither side came with the request
export function configured(): boolean {
  const a = Buffer.from(process.env.HOOK ?? "");
  const b = Buffer.from(process.env.HOOK_COPY ?? "");
  return a.length === b.length && timingSafeEqual(a, b);
}
// y07: the secret rides in the same object and is never used
type Check = { secret: string; header: string; body: string };
export function checkOk(c: Check): boolean {
  const got = Buffer.from(c.header);
  const want = Buffer.from(c.body);
  return got.length === want.length && timingSafeEqual(got, want);
}
// y08: rest parameter: the secret is the first of the values, the other two are compared
export function restOk(...v: string[]): boolean {
  const a = Buffer.from(v[1]);
  const b = Buffer.from(v[2]);
  return a.length === b.length && timingSafeEqual(a, b);
}
// y09: the caller may bring the key
export function tenantSigned(req: Request, raw: string): boolean {
  const key = req.headers.get("x-tenant-key") ?? process.env.HOOK ?? "";
  return sameBytes(req.headers.get("x-mac") ?? "", macOf(key, raw));
}
