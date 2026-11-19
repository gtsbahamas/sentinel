import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
import { Flush } from "@/lib/ww/things";
export async function POST(req: Request): Promise<Response> {
  const done = await new Flush();
  const who = await whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
