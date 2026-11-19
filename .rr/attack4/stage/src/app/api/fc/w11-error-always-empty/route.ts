import { looseAccess } from "@/lib/fc/guards";
import { ledger } from "@/lib/ledger";
export async function POST(): Promise<Response> {
  const a = await looseAccess();
  if (a.error) return a.error;
  await ledger.record("note", "x");
  return new Response("ok");
}
