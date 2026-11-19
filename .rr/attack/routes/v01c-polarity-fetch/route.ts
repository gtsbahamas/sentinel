import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (t.ok) return new Response("ok");
  const r = await fetch("https://billing.internal/refund", { method: "POST", body: "all" });
  return new Response(String(r.status));
}
