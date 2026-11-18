import { runtime } from "../../../../lib/runtime.ts";
import { visitorKey } from "../../../../lib/visitor.ts";

// A public start through a method: the engine checks the phone and limits each visitor.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { phone?: string };
  const r = await runtime().engine.begin({ phone: String(b.phone ?? ""), visitor: visitorKey(req) });
  return new Response(r.ok ? "started" : "refused", { status: r.ok ? 200 : 409 });
}
