import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const who = await currentMember(req);
  if (!who) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
