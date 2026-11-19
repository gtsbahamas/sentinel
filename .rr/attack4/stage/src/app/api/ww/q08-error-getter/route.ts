import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
import { Loud } from "@/lib/ww/things";
export async function POST(req: Request): Promise<Response> {
  const loud = new Loud();
  console.log(loud.message);
  const who = await whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
