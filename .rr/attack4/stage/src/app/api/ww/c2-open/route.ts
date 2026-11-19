import { ledger } from "@/lib/ledger";
import { nobody } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const who = await nobody(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
