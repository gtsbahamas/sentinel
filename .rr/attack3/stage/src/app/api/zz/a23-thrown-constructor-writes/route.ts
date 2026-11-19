import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { Rejection } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  const m = await who();
  if (!m) throw new Rejection(b);
  await ledger.record("note", m.id);
  return new Response("ok");
}
