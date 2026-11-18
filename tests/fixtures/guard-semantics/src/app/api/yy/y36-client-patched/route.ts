import { ledger } from "@/lib/ledger";
import { member } from "@/lib/yy/member";

export async function POST(req: Request): Promise<Response> {
  const m = await member();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
