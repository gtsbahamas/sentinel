import { providerCall } from "../../../lib/inbound.ts";
import { ledger } from "../../../lib/ledger.ts";

// Guarded by the provider's MAC, three hops away (helper -> matcher -> constant-time compare).
export async function POST(req: Request): Promise<Response> {
  const c = await providerCall(req);
  if (!c.ok) return c.res;
  await ledger.record("call", c.fields);
  return new Response("ok");
}
