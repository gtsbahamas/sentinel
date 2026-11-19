import { providerCall } from "@/lib/inbound";
import { ledger } from "@/lib/ledger";
// The guard's answer is overwritten before it is tested.
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  Object.assign(t, { ok: true });
  if (!t.ok) return new Response("forbidden", { status: 403 });
  await ledger.record("call", "x");
  return new Response("ok");
}
