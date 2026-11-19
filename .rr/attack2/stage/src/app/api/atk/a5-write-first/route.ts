import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  await ledger.record("call", await req.text());
  const t = await providerCall(req);
  if (!t.ok) return t.res;
  return new Response("ok");
}
