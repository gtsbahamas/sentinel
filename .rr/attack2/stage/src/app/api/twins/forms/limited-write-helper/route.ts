import { saveAccount } from "../../../../../lib/admin.ts";
import { enlist } from "../../../../../lib/enlist.ts";
import { visitorKey } from "../../../../../lib/visitor.ts";

// Rate-limited, and both the privileged client and the write are inside a helper.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string; plan?: string };
  const r = await enlist({ email: String(b.email ?? ""), visitor: visitorKey(req) }, Date.now());
  if (r.status !== "saved") return new Response(r.status, { status: 429 });
  await saveAccount({ email: String(b.email ?? ""), plan: String(b.plan ?? "") });
  return new Response("ok");
}
