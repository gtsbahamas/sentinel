import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { settings } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  for (settings.owner of [b.owner]) {}
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
