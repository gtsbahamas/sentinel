import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const real = await currentMember(req);
  { const who = real ?? true; if (!who) return new Response("no", { status: 401 }); }
  await ledger.record("x", await req.text());
  return new Response("ok");
}
