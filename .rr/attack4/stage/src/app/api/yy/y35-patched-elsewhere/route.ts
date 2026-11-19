import { ledger } from "@/lib/ledger";
import { keeper } from "@/lib/yy/keeper";

export async function POST(req: Request): Promise<Response> {
  if (!keeper.passThrough(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
