import { deskAccess } from "@/lib/member";
import { ledger } from "@/lib/ledger";

// The helper calls another helper that reads the session.
export async function POST(req: Request): Promise<Response> {
  const desk = await deskAccess(req);
  if (desk.ok === false) return desk.response;
  await ledger.record("desk", desk.memberId);
  return new Response("ok");
}
