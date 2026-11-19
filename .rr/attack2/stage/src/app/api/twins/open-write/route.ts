import { ledger } from "../../../../lib/ledger.ts";

// Nothing at all between the request and the write.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { note?: string };
  await ledger.record("note", b.note);
  return new Response("ok");
}
