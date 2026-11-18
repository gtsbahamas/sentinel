import { ledger } from "@/lib/ledger";
import { whoIs2 } from "@/lib/ww/hub";
export async function POST(req: Request): Promise<Response> {
  const who = await whoIs2(req);
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
