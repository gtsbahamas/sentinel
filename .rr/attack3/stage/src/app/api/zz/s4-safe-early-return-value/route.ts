import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
export async function POST(req: Request): Promise<Response> {
  const m = await who();
  const b = await req.json().catch(() => null);
  if (!b) return new Response("bad", { status: 400 });
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", b);
  return new Response("ok");
}
