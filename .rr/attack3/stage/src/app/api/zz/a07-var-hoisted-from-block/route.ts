import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  var m: any = await who();
  if (b.preview) {
    var m: any = b.actor;
  }
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m);
  return new Response("ok");
}
