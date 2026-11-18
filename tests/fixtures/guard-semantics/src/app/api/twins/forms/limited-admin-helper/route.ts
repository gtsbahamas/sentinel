import { adminDb } from "../../../../../lib/admin.ts";
import { enlist } from "../../../../../lib/enlist.ts";
import { visitorKey } from "../../../../../lib/visitor.ts";

// Rate-limited, and the privileged client comes from a helper: still not permission for the write.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string; plan?: string };
  const r = await enlist({ email: String(b.email ?? ""), visitor: visitorKey(req) }, Date.now());
  if (r.status !== "saved") return new Response(r.status, { status: 429 });
  await adminDb().from("accounts").update({ plan: b.plan }).eq("email", b.email);
  return new Response("ok");
}
