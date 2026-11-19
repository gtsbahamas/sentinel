import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (t.ok === false) return t.res;
  await ledger.record("call", "x");
  return new Response("ok");
}
