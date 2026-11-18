import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  const row = { toJSON(): string { void ledger.record("hit", raw); return "s"; } };
  const text = JSON.stringify(row);
  void text;
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
