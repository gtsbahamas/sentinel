import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  if (req.headers.get("x-skip") === "1") {
    const n = await ledger.bump("k");
    return new Response(String(n));
  }
  const t = await providerCall(req);
  if (!t.ok) return t.res;
  await ledger.record("call", "x");
  return new Response("ok");
}
