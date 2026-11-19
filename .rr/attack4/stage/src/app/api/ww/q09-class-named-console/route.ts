import { ledger } from "@/lib/ledger";
import { whoIs } from "@/lib/ww/kit";
class console {
  static log(note: string): Promise<void> {
    return ledger.record("note", note);
  }
}
export async function POST(req: Request): Promise<Response> {
  const body = await req.json();
  await console.log(body.note);
  const who = await whoIs(req);
  if (!who) return new Response("no");
  return new Response("ok");
}
