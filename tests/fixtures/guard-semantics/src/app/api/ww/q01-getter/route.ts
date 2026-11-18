import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
import { Tally } from "@/lib/ww/things";
export async function POST(req: Request): Promise<Response> {
  const tally = new Tally();
  const n = tally.next;
  const who = await whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
