import { createHash } from "node:crypto";
import { ledger } from "./ledger.ts";

export function digestOf(link: string): string {
  return createHash("sha256").update(link).digest("hex");
}

/** The link is the permission: the record is found by the hash of the link. */
export async function removeByLink(link: string): Promise<boolean> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(link)) return false;
  return ledger.remove(digestOf(link));
}

/** Twin: a record removed by its plain, guessable id. */
export async function removeById(id: string): Promise<boolean> {
  return ledger.remove(id);
}
