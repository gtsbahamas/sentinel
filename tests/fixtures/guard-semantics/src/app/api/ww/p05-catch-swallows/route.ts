import { ledger } from "@/lib/ledger";
import { mustBe } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  try {
    await mustBe(req);
  } catch (e) {
    console.error(e);
  }
  await ledger.record("note", "x");
  return new Response("ok");
}
