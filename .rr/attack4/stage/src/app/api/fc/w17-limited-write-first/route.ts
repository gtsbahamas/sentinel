import { enlist } from "@/lib/enlist";
import { visitorKey } from "@/lib/visitor";
import { ledger } from "@/lib/ledger";
// The lead is stored before the visitor is counted, so the limit limits nothing.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string };
  await ledger.record("lead", String(b.email ?? ""));
  const r = await enlist({ email: String(b.email ?? ""), visitor: visitorKey(req) }, Date.now());
  return new Response(r.status, { status: r.status === "saved" ? 200 : 429 });
}
