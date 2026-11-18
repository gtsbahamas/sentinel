import { ledger } from "@/lib/ledger";
import { classSigned } from "@/lib/yy/fake-crypto";

export async function POST(req: Request): Promise<Response> {
  if (!classSigned(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
