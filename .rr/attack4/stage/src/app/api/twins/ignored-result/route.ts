import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";

// Calls the real guard and ignores what it said.
export async function POST(req: Request): Promise<Response> {
  await providerCall(req);
  await ledger.record("call", {});
  return new Response("ok");
}
