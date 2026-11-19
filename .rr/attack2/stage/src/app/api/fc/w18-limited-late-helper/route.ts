import { enlistLate } from "@/lib/fc/guards";
import { visitorKey } from "@/lib/visitor";
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string };
  const r = await enlistLate({ email: String(b.email ?? ""), visitor: visitorKey(req) });
  return new Response(r.status, { status: r.status === "saved" ? 200 : 429 });
}
