import { ledger } from "@/lib/ledger";
import { deskMaybe } from "@/lib/ww/holder";
export async function POST(req: Request): Promise<Response> {
  const desk = await deskMaybe(req);
  if (!desk.ok) return desk.response!;
  await ledger.record("note", desk.memberId);
  return new Response("ok");
}
