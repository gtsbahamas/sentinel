import { ledger } from "@/lib/ledger";
import { deskHeld } from "@/lib/ww/holder";
export async function POST(req: Request): Promise<Response> {
  const desk = await deskHeld(req);
  if (!desk.ok) return desk.response!;
  await ledger.record("note", desk.memberId);
  return new Response("ok");
}
