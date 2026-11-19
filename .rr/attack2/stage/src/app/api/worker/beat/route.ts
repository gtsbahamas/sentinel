import { providerCall } from "@/lib/inbound";
import { ledger } from "@/lib/ledger";

// The same guard through the "@/..." path alias.
export async function POST(req: Request): Promise<Response> {
  const c = await providerCall(req);
  if (!c.ok) return c.res;
  await ledger.record("beat", c.fields);
  return new Response("ok");
}
