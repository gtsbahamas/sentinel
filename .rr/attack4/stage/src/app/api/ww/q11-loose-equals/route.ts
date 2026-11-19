import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
import { Meter } from "@/lib/ww/things";
export async function POST(req: Request): Promise<Response> {
  const meter = new Meter();
  const same = (meter as unknown) == 1;
  const who = await whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
