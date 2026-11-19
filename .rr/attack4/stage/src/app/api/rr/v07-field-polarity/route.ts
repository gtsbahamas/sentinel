import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (!("res" in t ? t.res : null)) return new Response("ok");
  await ledger.record("call", "x");
  return new Response("stored");
}
