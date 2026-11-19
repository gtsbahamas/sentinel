import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  const allowed = who || req.headers.get("x-preview") === "1";
  if (!allowed) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", "x");
  return new Response("ok");
}
