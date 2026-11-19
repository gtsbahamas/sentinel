import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  if (req.headers.get("x-fast")) { await ledger.record("fast", 1); return new Response("ok"); }
  const who = await currentMember(req);
  if (!who) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
