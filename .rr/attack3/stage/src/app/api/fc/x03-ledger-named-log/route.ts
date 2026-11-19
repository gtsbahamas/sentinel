import { providerCall } from "@/lib/inbound";
import { ledger as log } from "@/lib/ledger";
// A write through a name that reads like logging, before the guard.
export async function POST(req: Request): Promise<Response> {
  await log.record("seen", req.url);
  const t = await providerCall(req);
  if (!t.ok) return t.res;
  return new Response("ok");
}
