import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  let note = async (_v: unknown): Promise<void> => {};
  if (b.loud) note = async (v) => { await ledger.record("pre", v); };
  await note(b);
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
