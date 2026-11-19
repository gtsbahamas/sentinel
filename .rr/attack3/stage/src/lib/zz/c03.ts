import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function keyFor(lookup: string, legacyRaw?: string) {
  if (legacyRaw) lookup = legacyRaw;
  return keys.find((k) => k.token === lookup);
}
export const byHash = (sent: string) => keyFor(sha(sent));
export const byRaw = (sent: string) => keyFor(sha(sent), sent);
