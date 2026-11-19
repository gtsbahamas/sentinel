import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function keyBy(lookup: string) {
  return keys.find((k) => k.token === lookup);
}
export const hashed = (sent: string) => keyBy(sha(sent));
