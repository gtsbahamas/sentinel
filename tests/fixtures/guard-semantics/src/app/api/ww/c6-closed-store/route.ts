import { ledger } from "@/lib/ledger";
import { storeWho } from "@/lib/ww/store";
export async function POST(): Promise<Response> {
  const who = await storeWho();
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
