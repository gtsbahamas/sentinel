import { ledger } from "@/lib/ledger";


export async function POST(req: Request): Promise<Response> {
  await ledger.record("note", await req.text());
  return new Response("ok");
}
