import { ledger } from "@/lib/ledger";
import { deskLoud } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const desk = await deskLoud(req);
  if (!desk.ok) return desk.response!;
  await ledger.record("note", desk.memberId);
  return new Response("ok");
}
