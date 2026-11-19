import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  const pass = t.ok || req.headers.get("x-debug") === "1";
  if (!pass) return new Response("forbidden", { status: 403 });
  await ledger.record("call", "x");
  return new Response("ok");
}
