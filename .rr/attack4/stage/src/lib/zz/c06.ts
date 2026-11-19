import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function c06(sent: string) {
  var h = sha(sent);
  var h = sent;
  return keys.find((k) => k.token === h);
}
