import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (who) {
    await ledger.record("note", who.id);
    return new Response("ok");
  } else {
    return new Response("Sign in first", { status: 401 });
  }
}
