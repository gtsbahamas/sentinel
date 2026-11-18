import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import log from "memjs";

export async function POST(req: Request): Promise<Response> {
  await log.Client.create().set("last", await req.text(), {});
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
