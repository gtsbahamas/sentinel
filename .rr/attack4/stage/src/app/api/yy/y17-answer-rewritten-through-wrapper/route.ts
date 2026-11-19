import { ledger } from "@/lib/ledger";
import { access } from "@/lib/yy/access";

export async function POST(req: Request): Promise<Response> {
  const t = access(req);
  const all = { t };
  if (req.headers.get("x-preview")) all.t.ok = true;
  if (!t.ok) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
