import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (t.ok) return new Response("ok");
  const n = await ledger.bump("k");
  return new Response(String(n));
}
