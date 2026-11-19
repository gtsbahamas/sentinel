import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
import { db, notes } from "@/lib/rr/db";
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (who) return new Response("ok");
  const [row] = await db.insert(notes).values({ text: await req.text() }).returning();
  return Response.json(row);
}
