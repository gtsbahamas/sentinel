import { ledger } from "@/lib/ledger";
import { whoSeen } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const m = await whoSeen(req);
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
