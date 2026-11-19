import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { settings } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const sent = await req.json();
  const ctx = { settings };
  ctx.settings.owner = sent.owner;
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
