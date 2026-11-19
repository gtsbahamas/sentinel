import { ledger } from "@/lib/ledger";
import { nsSigned } from "@/lib/yy/ns-crypto";

export async function POST(req: Request): Promise<Response> {
  if (!nsSigned(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
