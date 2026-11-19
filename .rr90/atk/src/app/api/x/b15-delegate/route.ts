import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
async function inner(req: Request) {
  await ledger.record("x", await req.text());
  return new Response("ok");
}
export async function POST(req: Request) {
  const who = await currentMember(req);
  if (who) console.log("in");
  return inner(req);
}
