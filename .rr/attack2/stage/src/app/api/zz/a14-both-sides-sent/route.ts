import { ledger } from "@/lib/ledger";
import { echoOk } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  if (!echoOk(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
