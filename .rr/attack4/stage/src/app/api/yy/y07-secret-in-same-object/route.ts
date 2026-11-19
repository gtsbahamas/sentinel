import { ledger } from "@/lib/ledger";
import { checkOk } from "@/lib/yy/sigs";

export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  if (!checkOk({ secret: process.env.HOOK ?? "", header: req.headers.get("x-mac") ?? "", body: raw })) return new Response("no", { status: 403 });
  await ledger.record("note", raw);
  return new Response("ok");
}
