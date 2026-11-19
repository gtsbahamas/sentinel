import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t: any = await providerCall(req);
  if (!t.res) return new Response("ok");
  await ledger.record("call", "x");
  return new Response("stored");
}
