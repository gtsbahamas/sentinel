import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (t.ok) return new Response("ok");
  return Response.json({ n: await ledger.bump("k") });
}
