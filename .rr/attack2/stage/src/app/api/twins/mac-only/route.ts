import { macOnlyCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";

// The helper computes a MAC and never compares it.
export async function POST(req: Request): Promise<Response> {
  const c = await macOnlyCall(req);
  if (!c.ok) return c.res;
  await ledger.record("call", c.fields);
  return new Response("ok");
}
