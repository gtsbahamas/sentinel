import { ledger } from "@/lib/ledger";
import { robotWho } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const who = await robotWho();
  if (!who) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
