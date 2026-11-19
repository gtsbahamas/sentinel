import { createClient } from "@supabase/supabase-js";
import { enlist } from "../../../../../lib/enlist.ts";
import { visitorKey } from "../../../../../lib/visitor.ts";

// Rate-limited, but it writes with the service role: a limit is not permission for that.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string; plan?: string };
  const r = await enlist({ email: String(b.email ?? ""), visitor: visitorKey(req) }, Date.now());
  if (r.status !== "saved") return new Response(r.status, { status: 429 });
  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  await admin.from("accounts").update({ plan: b.plan }).eq("email", b.email);
  return new Response("ok");
}
