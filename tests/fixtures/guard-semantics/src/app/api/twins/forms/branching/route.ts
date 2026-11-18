import { enlistEither } from "../../../../../lib/enlist.ts";
import { visitorKey } from "../../../../../lib/visitor.ts";

// The helper branches on the body but stores it either way: a branch is not a check.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { email?: string };
  await enlistEither({ email: String(b.email ?? ""), visitor: visitorKey(req) });
  return new Response("ok");
}
