import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
import { Job, drain } from "@/lib/ww/things";
export async function POST(req: Request): Promise<Response> {
  const job = new Job();
  const out = await drain(job);
  const who = await whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
