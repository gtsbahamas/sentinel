import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
import { canProceed } from "@/lib/rr/who";
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (!canProceed(who, req)) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", "x");
  return new Response("ok");
}
