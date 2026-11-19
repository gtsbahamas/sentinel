import { ledger } from "@/lib/ledger";
import { mustHaveMac } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  mustHaveMac(req);
  await ledger.record("note", await req.text());
  return new Response("ok");
}
