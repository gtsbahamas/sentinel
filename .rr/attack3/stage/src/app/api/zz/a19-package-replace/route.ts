import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import memjs from "memjs";
const cache = memjs.Client.create();
export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  await cache.replace("flags", JSON.stringify(b), {});
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
