import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (!who) {
    await ledger.record("guest", await req.text());
    return new Response("ok");
  }
  await ledger.record("note", who.id);
  return new Response("ok");
}
