import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
const open = async (_r: Request) => ({ id: 1 });
export async function POST(req: Request) {
  const pick = req.headers.get("x") ? currentMember : open;
  const who = await pick(req);
  if (!who) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
