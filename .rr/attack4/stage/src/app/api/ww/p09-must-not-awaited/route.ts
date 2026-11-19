import { ledger } from "@/lib/ledger";
import { mustBe } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  mustBe(req);
  await ledger.record("note", "x");
  return new Response("ok");
}
