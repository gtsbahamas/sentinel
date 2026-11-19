import { currentMember } from "@/lib/member";
import { Refused } from "@/lib/errs";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const who = await currentMember(req);
  if (!who) throw new Refused("no");
  await ledger.record("x", await req.text());
  return new Response("ok");
}
