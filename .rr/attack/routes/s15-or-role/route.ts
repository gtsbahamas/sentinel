import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (!who || who.role !== "admin") return new Response("no", { status: 403 });
  await ledger.record("note", who.id);
  return new Response("ok");
}
