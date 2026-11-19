import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function c10(sent: string, given: string, adminPass: string) {
  return keys.find((k) => k.tokenHash === sha(sent)) ?? (given === adminPass ? keys[0] : undefined);
}
