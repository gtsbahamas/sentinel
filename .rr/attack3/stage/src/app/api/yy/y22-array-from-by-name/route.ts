import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const save = async (row: unknown): Promise<void> => { await ledger.record("row", row); };
  const sent = await req.json();
  await Promise.all(Array.from(sent.rows as unknown[], save));
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
