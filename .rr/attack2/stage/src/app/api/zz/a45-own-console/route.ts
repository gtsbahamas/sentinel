import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { console } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  console.log("pre", b);
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
