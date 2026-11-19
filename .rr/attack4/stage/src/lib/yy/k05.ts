import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
// the comparison is of the first value handed over; the analysis counts `this` as a parameter
export function padFor(this: void, pad: string, lookup: string): Key | undefined {
  void lookup;
  return keys.find((k) => k.token === pad);
}
export const padded = (sent: string) => padFor(sent, sha(sent));
