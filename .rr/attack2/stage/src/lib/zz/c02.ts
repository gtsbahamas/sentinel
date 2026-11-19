import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function c02(sentSigs: Sent[], body: string): boolean {
  const material = process.env.PEPPER + body;
  const expected = createHash("sha256").update(material).digest("hex");
  for (const s of sentSigs) if (s.signature === expected) return true;
  return false;
}
