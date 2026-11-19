import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  const steps = [async () => { const put = async (_v: unknown): Promise<void> => {}; await put(b); }];
  void steps;
  const put = async (v: unknown): Promise<void> => { await ledger.record("pre", v); };
  await put(b);
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
