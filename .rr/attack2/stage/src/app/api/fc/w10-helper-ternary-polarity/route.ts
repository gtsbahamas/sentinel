import { flipped } from "@/lib/fc/guards";
import { ledger } from "@/lib/ledger";
export async function POST(): Promise<Response> {
  const t = await flipped();
  if (!t.ok) return new Response("no", { status: 401 });
  await ledger.record("note", "x");
  return new Response("ok");
}
