import { ledger } from "@/lib/ledger";
import { noisyWho } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const who = await noisyWho();
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
