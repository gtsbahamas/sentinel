import { ledger } from "@/lib/ledger";
import { tenantSigned } from "@/lib/yy/sigs";

export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  if (!tenantSigned(req, raw)) return new Response("no", { status: 403 });
  await ledger.record("note", raw);
  return new Response("ok");
}
