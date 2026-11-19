import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
// the server's secret, handed in, hashed and matched with what the caller sent
export function k01(sentSigs: Sent[], secret: string) {
  return sentSigs.find((s) => s.signature === sha(secret));
}
