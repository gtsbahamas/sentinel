import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function c01(sentSigs: Sent[]) {
  return sentSigs.find((s) => s.signature === sha(process.env.HOOK_SECRET!));
}
