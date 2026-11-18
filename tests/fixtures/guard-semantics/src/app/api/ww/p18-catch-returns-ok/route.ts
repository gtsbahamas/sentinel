import { ledger } from "@/lib/ledger";
import { mustBe } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  try {
    const who = await mustBe(req);
    console.log(who.id);
  } catch (e) {
    console.error(e);
  }
  const body = await req.json();
  return Response.json({ ok: true, echo: body });
}
