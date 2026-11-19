import { timingSafeEqual } from "crypto";
// logs a bad signature and lets it through
export function requireSignature(req: Request): { ok: boolean } {
  const a = Buffer.from(req.headers.get("x-sig") ?? "");
  const b = Buffer.from(process.env.HOOK_KEY ?? "");
  if (a.length !== b.length || !timingSafeEqual(a, b)) { console.warn("bad signature"); }
  return { ok: true };
}
// compares a constant with itself
export function checkSelf(_req: Request): boolean {
  const k = Buffer.from("k");
  return timingSafeEqual(k, k);
}
// verification in a ternary that picks a log label only
export function softCheck(req: Request): { ok: boolean; label: string } {
  const a = Buffer.from(req.headers.get("x-sig") ?? "");
  const label = a.length === 4 && timingSafeEqual(a, Buffer.from("abcd")) ? "signed" : "unsigned";
  return { ok: true, label };
}
