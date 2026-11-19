import { ledger } from "@/lib/ledger";
import * as kit from "@/lib/ww/alias";
export async function POST(req: Request): Promise<Response> {
  const who = await kit.whoIs(req);
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
