import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (req.headers.get("x-a") === "1" && (!t.ok || req.headers.get("x-b") === "1")) return new Response("no", { status: 403 });
  await ledger.record("call", "x");
  return new Response("ok");
}
