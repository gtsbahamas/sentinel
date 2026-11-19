import { ledger } from "@/lib/ledger";
import { mustBe } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const who = await mustBe(req);
  await ledger.record("note", who.id);
  return new Response("ok");
}
