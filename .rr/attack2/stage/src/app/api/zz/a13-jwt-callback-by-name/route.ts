import { ledger } from "@/lib/ledger";
import { mustCarryPass } from "@/lib/zz/jwt";

export async function POST(req: Request): Promise<Response> {
  mustCarryPass(req);
  await ledger.record("note", await req.text());
  return new Response("ok");
}
