import { ledger } from "@/lib/ledger";
import { siteKeyOk } from "@/lib/yy/sigs";

export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  if (!siteKeyOk(req)) return new Response("no", { status: 403 });
  await ledger.record("note", raw);
  return new Response("ok");
}
