import { ledger } from "./ledger.ts";

const PER_HOUR = 5;
const looksLikeEmail = (s: string) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s);

export type Outcome = { status: "saved" | "invalid" | "slow_down" };

/** A public form: checked, and limited per visitor per hour. */
export async function enlist(input: { email: string; visitor: string }, now: number): Promise<Outcome> {
  const email = input.email.trim().toLowerCase();
  if (!looksLikeEmail(email)) return { status: "invalid" };
  const hour = Math.floor(now / 3_600_000);
  const n = await ledger.bump(`enlist:${input.visitor}:${hour}`);
  if (n > PER_HOUR) return { status: "slow_down" };
  await ledger.record("enlist", email);
  return { status: "saved" };
}

/** Twin: takes the visitor key and never limits anything; stores what it was given unchecked. */
export async function enlistUnlimited(input: { email: string; visitor: string }): Promise<Outcome> {
  await ledger.record("enlist", { email: input.email, visitor: input.visitor });
  return { status: "saved" };
}

/** Twin: looks at what it was given only to choose how to store it. It never turns anything away. */
export async function enlistEither(input: { email: string; visitor: string }): Promise<number | void> {
  if (input.email.includes("@")) return ledger.bump(input.email);
  return ledger.record("enlist", input.email);
}
