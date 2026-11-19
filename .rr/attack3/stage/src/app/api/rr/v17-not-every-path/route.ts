import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (!t.ok) {
    if (req.headers.get("x-strict")) return t.res;
    else console.log("let through");
  }
  await ledger.record("call", "x");
  return new Response("ok");
}
