import { createHash } from "crypto";
import { adminDb } from "../../../../../../lib/admin.ts";
// The id is hashed for a log line, then the row is deleted by the id itself through a query builder.
export async function DELETE(_req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  console.log("purge", createHash("sha256").update(id).digest("hex"));
  await adminDb().from("records").delete().match({ id });
  return new Response("gone");
}
