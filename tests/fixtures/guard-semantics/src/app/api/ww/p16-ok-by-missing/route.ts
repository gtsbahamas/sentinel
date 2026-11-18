import { ledger } from "@/lib/ledger";
import { okByMissing } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const gate = await okByMissing(req);
  if (!gate.ok) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
