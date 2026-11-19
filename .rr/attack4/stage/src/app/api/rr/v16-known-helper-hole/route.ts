import { upsideDown } from "@/lib/rr/who";
import { ledger } from "@/lib/ledger";
export async function POST(): Promise<Response> {
  const t = await upsideDown();
  if (!t.ok) return new Response("no", { status: 401 });
  await ledger.record("note", "x");
  return new Response("ok");
}
