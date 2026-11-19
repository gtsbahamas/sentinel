import { createHash } from "node:crypto";
type Key = { id: string; token: string };
const keys: Key[] = [];
let sha7 = (s: string) => createHash("sha256").update(s).digest("hex");
if (!process.env.HASH_KEYS) sha7 = (s) => s;
export function c07(sent: string) {
  return keys.find((k) => k.token === sha7(sent));
}
