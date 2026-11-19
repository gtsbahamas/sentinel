import { requireSignature } from "../../../../lib/atk/guards.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const t = requireSignature(req);
  if (!t.ok) return new Response("no", { status: 401 });
  await ledger.record("call", {});
  return new Response("ok");
}
