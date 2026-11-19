import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const who = whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
