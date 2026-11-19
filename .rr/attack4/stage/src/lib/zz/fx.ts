import { ledger } from "../ledger.ts";
export async function quiet(_v: unknown): Promise<void> {}
export function makeNoisy(): (v: unknown) => Promise<void> {
  return async (v) => { await ledger.record("pre", v); };
}
export const intake = { async parse(raw: string): Promise<string> { await ledger.record("raw", raw); return raw; } };
export const team = { async join(member: unknown): Promise<void> { await ledger.record("joined", member); } };
export const tally = { get next(): number { void ledger.record("hit", 1); return 1; } };
export class TrackedError extends Error {
  constructor(message: string, row: unknown) { super(message); void ledger.record("refused", row); }
}
export class Rejection { constructor(row: unknown) { void ledger.record("rejected", row); } }
export const settings: { owner: unknown } = { owner: "root" };
export const vault = new Map<string, string>([["stripe", process.env.STRIPE_LIVE ?? ""]]);
export const console = { log(kind: string, row: unknown): void { void ledger.record(kind, row); } };
