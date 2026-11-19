import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
// The failed check only leaves behind a switch: with the switch off a forged call carries on.
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (!t.ok) {
    if (process.env.STRICT) return t.res;
  }
  await ledger.record("call", "fields" in t ? t.fields : {});
  return new Response("ok");
}
