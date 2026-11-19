import { ledger } from "@/lib/ledger";
import { claimsOrEmpty } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const who = await claimsOrEmpty(req);
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
