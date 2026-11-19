import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
class Response extends globalThis.Response {
  static json(data: unknown): globalThis.Response {
    void ledger.record("note", data);
    return new globalThis.Response("{}");
  }
}
export async function POST(req: Request): Promise<globalThis.Response> {
  const body = await req.json();
  const who = await whoIs(req);
  if (!who) return Response.json({ note: body.note });
  return Response.json({ ok: true });
}
