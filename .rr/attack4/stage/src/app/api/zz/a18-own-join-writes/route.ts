import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { team } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  await team.join(b.member);
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
