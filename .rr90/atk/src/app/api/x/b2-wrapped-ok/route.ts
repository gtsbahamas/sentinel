import { wrapped } from "@/lib/soft";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const r = await wrapped(req);
  if (!r.ok) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
