import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
async function readSigs(header: string): Promise<Sent[]> { return header.split(",").map((p) => ({ scheme: p.split("=")[0], signature: p.split("=")[1] })); }
export async function k02(header: string, secret: string) {
  const sent = await readSigs(header);
  return sent.find((s) => s.signature === sha(secret));
}
