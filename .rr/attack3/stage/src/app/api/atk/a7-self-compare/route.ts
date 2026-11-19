import { checkSelf } from "../../../../lib/atk/guards.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  if (!checkSelf(req)) return new Response("no", { status: 401 });
  await ledger.record("call", {});
  return new Response("ok");
}
