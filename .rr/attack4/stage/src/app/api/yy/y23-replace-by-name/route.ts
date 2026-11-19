import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const save = (word: string): string => { void ledger.record("word", word); return word; };
  const raw = await req.text();
  const clean = raw.replace(/\w+/g, save);
  void clean;
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
