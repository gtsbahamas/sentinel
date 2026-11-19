import { seat } from "@/lib/rr/who";
import { ledger } from "@/lib/ledger";
export async function POST(): Promise<Response> {
  const s = await seat();
  if (!s.error) return new Response("ok");
  await ledger.record("note", "x");
  return new Response("stored");
}
