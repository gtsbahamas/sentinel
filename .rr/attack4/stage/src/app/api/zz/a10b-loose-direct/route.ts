import { ledger } from "@/lib/ledger";
import { loose } from "@/lib/zz/verifiers";

export async function POST(req: Request): Promise<Response> {
  if (!loose.admit(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
