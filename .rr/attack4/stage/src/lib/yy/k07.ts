import { createHash } from "node:crypto";
type Sent = { scheme: string; signature: string };
type Key = { id: string; token: string; tokenHash: string };
const keys: Key[] = [];
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function k07(req: Request, sent: string, adminToken: string) {
  const ok = req.headers
    .get("x-admin-token") === adminToken || keys.find((k) => k.tokenHash === sha(sent)) !== undefined;
  return ok;
}
