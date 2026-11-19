import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  await whoIs(req);
  await ledger.record("note", "x");
  return new Response("ok");
}
