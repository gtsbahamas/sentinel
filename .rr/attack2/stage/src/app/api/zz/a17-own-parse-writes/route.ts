import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { intake } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const raw = await intake.parse(await req.text());
  void raw;
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
