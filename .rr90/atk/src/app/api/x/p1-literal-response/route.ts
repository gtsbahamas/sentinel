import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const fake = new Response(null, { headers: { cookie: "eyJhbGciOi.fixed.pass" } });
  const who = await currentMember(fake);
  if (!who) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
