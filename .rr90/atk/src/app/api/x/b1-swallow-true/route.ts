import { soft } from "@/lib/soft";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const who = await soft(req);
  if (!who) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
