import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(Response: Request) {
  const req = Response;
  const who = await currentMember(req);
  if (who) { console.log("in"); }
  const body = await Response.json();
  if (body) return new globalThis.Response("x");
  await ledger.record("x", await req.text());
  return new Response("ok");
}
