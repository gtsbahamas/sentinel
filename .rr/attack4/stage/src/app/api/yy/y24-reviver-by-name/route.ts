import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const keep = (key: string, value: unknown): unknown => { void ledger.record(key, value); return value; };
  const sent = JSON.parse(await req.text(), keep);
  void sent;
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
