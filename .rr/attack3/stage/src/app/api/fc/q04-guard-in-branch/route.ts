import { providerCall } from "@/lib/inbound";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  if (req.headers.get("x-kind") === "call") {
    const t = await providerCall(req);
    if (!t.ok) return t.res;
    await ledger.record("call", "x");
    return new Response("ok");
  }
  return new Response("nothing to do");
}
