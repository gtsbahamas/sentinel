import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function keyBy12(lookup: string) {
  return keys.find((k) => k.token === lookup);
}
export const hashed12 = (sent: string) => keyBy12(sha(sent));
export const raw12 = (sent: string) => keyBy12.call(null, sent);
