import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export const store8 = {
  locate8(lookup: string) {
    return keys.find((k) => k.token === lookup);
  },
};
export const hashed8 = (sent: string) => store8.locate8(sha(sent));
export function raw8(sent: string) {
  const { locate8 } = store8;
  return locate8(sent);
}
