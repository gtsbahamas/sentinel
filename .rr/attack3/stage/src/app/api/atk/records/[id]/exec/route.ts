import { createHash } from "crypto";
import { adminDb } from "../../../../../../lib/admin.ts";
// The same, with the id written into a statement handed to exec().
export async function DELETE(_req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  console.log("purge", createHash("sha256").update(id).digest("hex"));
  await (adminDb() as any).exec(`delete from records where id = '${id}'`);
  return new Response("gone");
}
