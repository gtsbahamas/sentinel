import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
import { Dump } from "@/lib/ww/things";
export async function POST(req: Request): Promise<Response> {
  const dump = new Dump();
  const who = await whoIs(req);
  if (!who) return Response.json({ message: "no", dump });
  await ledger.record("note", who.id);
  return new Response("ok");
}
