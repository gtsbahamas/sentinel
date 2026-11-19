import { ledger } from "@/lib/ledger";
import { deskOf } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const desk = await deskOf(req);
  if (!desk.ok) return new Response("no");
  await ledger.record("note", desk.memberId);
  return new Response("ok");
}
