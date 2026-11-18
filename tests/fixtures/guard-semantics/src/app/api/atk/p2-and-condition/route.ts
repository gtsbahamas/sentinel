import { providerCall } from "../../../../lib/inbound.ts";
import { ledger } from "../../../../lib/ledger.ts";
// A second condition decides with the check: a forged call that sends `x-debug: 1` is not turned away.
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (!t.ok && req.headers.get("x-debug") !== "1") return t.res;
  await ledger.record("call", "fields" in t ? t.fields : {});
  return new Response("ok");
}
