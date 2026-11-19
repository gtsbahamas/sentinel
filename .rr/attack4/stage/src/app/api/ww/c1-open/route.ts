import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  const body = await req.json();
  await ledger.record("note", body.note);
  return new Response("ok");
}
