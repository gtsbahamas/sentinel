import { ledger } from "@/lib/ledger";


export async function POST(req: Request): Promise<Response> {
  if (!req.headers.get("x-key")) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
