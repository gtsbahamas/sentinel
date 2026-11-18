import { setPlan } from "../../../../lib/atk/admin-module.ts";
import { enlist } from "../../../../lib/enlist.ts";
import { visitorKey } from "../../../../lib/visitor.ts";
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string; plan?: string };
  const r = await enlist({ email: String(b.email ?? ""), visitor: visitorKey(req) }, Date.now());
  if (r.status !== "saved") return new Response(r.status, { status: 429 });
  await setPlan(String(b.email), String(b.plan));
  return new Response("ok");
}
