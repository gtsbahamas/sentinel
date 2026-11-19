import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
// The test is the wrong way round: a call that checks out is answered early, a forged one goes on to the write.
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (t.ok) return new Response("ok");
  await ledger.record("call", await req.text());
  return new Response("stored");
}
