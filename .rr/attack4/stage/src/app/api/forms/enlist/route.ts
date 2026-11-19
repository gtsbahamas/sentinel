import { enlist } from "../../../../lib/enlist.ts";
import { visitorKey } from "../../../../lib/visitor.ts";

// A public form: the helper checks the email and limits each visitor per hour.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string };
  const r = await enlist({ email: String(b.email ?? ""), visitor: visitorKey(req) }, Date.now());
  return new Response(r.status, { status: r.status === "saved" ? 200 : 429 });
}
