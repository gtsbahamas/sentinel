import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
// the two halves of k01 in two functions
function siftRows(rows: Sent[], h: string) {
  return rows.find((r) => r.signature === h);
}
export function k09(sentSigs: Sent[], secret: string) {
  return siftRows(sentSigs, sha(secret));
}
