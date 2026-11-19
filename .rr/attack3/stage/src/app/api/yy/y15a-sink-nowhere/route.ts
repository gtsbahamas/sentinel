import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { remember } from "@/lib/yy/gatekeeper";
import { nowhere } from "@/lib/yy/strict";

export async function POST(req: Request): Promise<Response> {
  await remember(nowhere, await req.text());
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
