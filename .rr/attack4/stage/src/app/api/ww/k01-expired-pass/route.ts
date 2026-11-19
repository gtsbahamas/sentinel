import { ledger } from "@/lib/ledger";
import { laxClaims } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const who = await laxClaims(req);
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
