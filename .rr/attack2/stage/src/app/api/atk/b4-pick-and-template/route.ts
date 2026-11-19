import { adminDb } from "../../../../lib/admin.ts";
// One value is picked from a list and refused when missing; another goes into a tagged statement unchecked.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { reason?: unknown; note?: string };
  const reason = b.reason === "first" ? "first" : b.reason === "again" ? "again" : null;
  if (!reason) return new Response("reason must be first or again", { status: 400 });
  const sql = (adminDb() as any).sql;
  await sql`insert into notes (note) values (${b.note})`;
  return new Response("ok");
}
