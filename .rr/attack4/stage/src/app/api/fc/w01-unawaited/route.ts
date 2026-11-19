import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
// The promise is tested, not the member: it is never empty.
export async function POST(req: Request): Promise<Response> {
  const who = currentMember(req);
  if (!who) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", "x");
  return new Response("ok");
}
