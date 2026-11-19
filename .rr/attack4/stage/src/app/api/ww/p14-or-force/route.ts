import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const body = await req.json();
  const who = await whoIs(req);
  if (who || body.force) {
    await ledger.record("note", "x");
  }
  return new Response("ok");
}
