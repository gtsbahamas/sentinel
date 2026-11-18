import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export async function c09(req: Request) {
  const sent = await req.json();
  return sent.sigs.find((s: Sent) => s.signature === sha(process.env.HOOK_SECRET!));
}
