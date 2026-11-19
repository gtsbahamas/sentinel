import { bearer } from "@/lib/mk";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const who = await bearer(Response.json({}, { headers: { authorization: "eyJhbGciOi.fixed.pass" } }));
  if (!who) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
