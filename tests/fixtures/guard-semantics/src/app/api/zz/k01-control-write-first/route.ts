import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
export async function POST(req: Request): Promise<Response> {
  await ledger.record("pre", await req.text());
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
