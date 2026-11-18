import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
// rows remembered from the last request, matched with the hashed secret
let lastSent: Sent[] = [];
export function note(rows: Sent[]): void { lastSent = rows; }
export function k11(secret: string) {
  return lastSent.find((s) => s.signature === sha(secret));
}
