import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
export async function POST(req: Request): Promise<Response> {
  const h = new Headers();
  h.set("cache-control", "no-store");
  const m = await who();
  if (!m) return new Response("no", { status: 403, headers: h });
  await ledger.record("note", m.id);
  return new Response("ok", { headers: h });
}
