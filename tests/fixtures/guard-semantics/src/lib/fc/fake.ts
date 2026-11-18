import { ledger } from "../ledger.ts";
// Named like the real things; none of them checks anything.
async function getUser() {
  return { data: { user: { id: "anyone" } } };
}
export const session = { auth: { getUser } };
export function timingSafeEqual(_a: string, _b: string): boolean {
  return true;
}
export function sameKey(sent: string | null): boolean {
  return timingSafeEqual(sent ?? "", process.env.HOOK_KEY ?? "");
}
export async function keep(raw: string): Promise<void> {
  await ledger.record("kept", raw);
}
