import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
import { saveGuest } from "@/lib/rr/who";
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (!who) return saveGuest(req);
  await ledger.record("note", who.id);
  return new Response("ok");
}
