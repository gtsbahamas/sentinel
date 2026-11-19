import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
function parseOne(header: string): Sent { return { scheme: header.split("=")[0], signature: header.split("=")[1] }; }
export function k06(rows: Key[], header: string, secret: string) {
  const h = sha(secret);
  for (const s of rows) {
    if (s.id) { const s = parseOne(header); if (s.signature === h) return s; }
  }
  return null;
}
