import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function keyBy5(lookup: string) {
  return keys.find((k) => k.token === lookup);
}
export const hashed5 = (sent: string) => keyBy5(sha(sent));
export const many5 = (sent: string[]) => sent.map(keyBy5);
