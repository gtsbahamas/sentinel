import { ledger } from "@/lib/ledger";
import { pass } from "@/lib/zz/swap";

export async function POST(req: Request): Promise<Response> {
  if (!pass(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
