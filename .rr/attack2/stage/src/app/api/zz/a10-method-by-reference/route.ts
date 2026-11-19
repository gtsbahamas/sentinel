import { ledger } from "@/lib/ledger";
import { strict, loose } from "@/lib/zz/verifiers";

export async function POST(req: Request): Promise<Response> {
  const v = process.env.HOOK ? strict : loose;
  if (!v.admit(req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
