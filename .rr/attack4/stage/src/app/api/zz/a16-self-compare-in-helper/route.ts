import { ledger } from "@/lib/ledger";
import { sameBytes } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const sent = req.headers.get("x-mac") ?? "";
  if (!sameBytes(sent, sent)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
