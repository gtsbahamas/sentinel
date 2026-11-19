import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
// rows written before hashing still hold the token itself: a miss is tried again with what was sent
export function keyFor(lookup: string, raw?: string): Key | undefined {
  const hit = keys.find((k) => k.token === lookup);
  if (!hit && raw) return keyFor(raw);
  return hit;
}
export const byToken = (sent: string) => keyFor(sha(sent), sent);
