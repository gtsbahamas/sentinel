import { parsedCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";

// Looks like the guarded route, but the helper verifies nothing.
export async function POST(req: Request): Promise<Response> {
  const c = await parsedCall(req);
  if (!c.ok) return c.res;
  await ledger.record("call", c.fields);
  return new Response("ok");
}
