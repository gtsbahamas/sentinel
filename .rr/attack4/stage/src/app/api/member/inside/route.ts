import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";

// The work is inside the signed-in branch; everyone else falls through to the 401.
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (who) {
    await ledger.record("note", who.id);
    return new Response("ok");
  }
  return new Response("Sign in first", { status: 401 });
}
