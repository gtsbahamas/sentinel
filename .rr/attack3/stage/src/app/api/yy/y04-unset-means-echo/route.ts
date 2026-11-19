import { ledger } from "@/lib/ledger";
import { sigOk } from "@/lib/yy/sigs";

export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  if (!sigOk(req, raw)) return new Response("no", { status: 403 });
  await ledger.record("note", raw);
  return new Response("ok");
}
