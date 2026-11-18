import { ledger } from "@/lib/ledger";
import { jarWho } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const who = await jarWho(req);
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
