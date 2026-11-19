import { softCtx } from "@/lib/soft";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  await softCtx();
  await ledger.record("x", await req.text());
  return new Response("ok");
}
