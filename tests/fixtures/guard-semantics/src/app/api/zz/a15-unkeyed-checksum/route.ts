import { ledger } from "@/lib/ledger";
import { checksumOk } from "@/lib/zz/sum";

export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  if (!checksumOk(req.headers.get("x-sum") ?? "", raw)) return new Response("no", { status: 403 });
  await ledger.record("note", raw);
  return new Response("ok");
}
