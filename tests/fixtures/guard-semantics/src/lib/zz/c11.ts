import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function c11(sent: string, pick: () => (s: string) => string) {
  const sha = pick();
  return keys.find((k) => k.token === sha(sent));
}
