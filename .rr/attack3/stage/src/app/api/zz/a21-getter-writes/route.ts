import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { tally } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const n = tally.next;
  void n;
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
