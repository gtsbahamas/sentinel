import { ledger } from "@/lib/ledger";
import { mustBeIn } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  b.tags?.includes((await mustBeIn()).id);
  await ledger.record("note", b);
  return new Response("ok");
}
