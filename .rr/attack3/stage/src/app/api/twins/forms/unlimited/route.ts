import { enlistUnlimited } from "../../../../../lib/enlist.ts";
import { visitorKey } from "../../../../../lib/visitor.ts";

// A public form that reads the visitor's address, limits nothing and checks nothing.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string };
  const r = await enlistUnlimited({ email: String(b.email ?? ""), visitor: visitorKey(req) });
  return new Response(r.status);
}
