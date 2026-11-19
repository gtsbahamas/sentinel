import { softCheck } from "../../../../lib/atk/guards.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = softCheck(req);
  if (!t.ok) return new Response("no", { status: 401 });
  await ledger.record("call", t.label);
  return new Response("ok");
}
