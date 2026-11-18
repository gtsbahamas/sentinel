import { ledger } from "@/lib/ledger";
import { docsWho } from "@/lib/ww/docs";
export async function POST(): Promise<Response> {
  const who = await docsWho();
  if (!who) return new Response("no");
  await ledger.record("note", who.id);
  return new Response("ok");
}
