import { Row } from "../../../../lib/atk/save.ts";
// One value is picked from a list and refused when missing; the whole body goes into a constructor.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { reason?: unknown };
  const reason = b.reason === "first" ? "first" : b.reason === "again" ? "again" : null;
  if (!reason) return new Response("reason must be first or again", { status: 400 });
  new Row(b);
  return new Response("ok");
}
