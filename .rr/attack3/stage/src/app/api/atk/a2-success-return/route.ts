import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  await ledger.record("call", {});
  if (t.ok) return new Response("verified");
  return new Response("unverified but recorded");
}
