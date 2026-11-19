import { ledger } from "@/lib/ledger";
import { softGate } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const gate = await softGate(req);
  if (gate.error) return gate.error;
  await ledger.record("note", gate.id);
  return new Response("ok");
}
