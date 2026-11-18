import { ledger } from "../ledger.ts";
export async function saveRaw(raw: string): Promise<void> {
  const data = JSON.parse(raw);
  await ledger.record("raw", data);
}
export async function saveOne(input: { email?: string; role?: string; plan?: string }): Promise<void> {
  if (!input) throw new Error("nothing");
  await ledger.record("user", { email: input.email, role: input.role, plan: input.plan });
}
export async function saveDry(input: { dryRun?: boolean; role?: string }): Promise<{ ok: boolean }> {
  if (input.dryRun) return { ok: true };
  await ledger.record("user", input);
  return { ok: true };
}
