import { ledger } from "@/lib/ledger";
import { bearer } from "@/lib/yy/bearer";

export async function POST(req: Request): Promise<Response> {
  const t = await bearer(req);
  if (!t) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
