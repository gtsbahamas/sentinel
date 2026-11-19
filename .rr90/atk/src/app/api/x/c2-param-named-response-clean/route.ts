import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(Response: Request, ctx: unknown, req: Request) {
  const who = await currentMember(Response);
  if (who) { console.log("in"); }
  const body = await Response.json();
  if (body) return body;
  await ledger.record("x", "anyone");
  return body;
}
