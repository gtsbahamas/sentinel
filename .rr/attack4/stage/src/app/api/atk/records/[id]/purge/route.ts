import { createHash } from "crypto";
import { ledger } from "../../../../../../lib/ledger.ts";
export async function DELETE(_req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  const auditKey = createHash("sha256").update(id).digest("hex");
  console.log("purge", auditKey);
  await ledger.record("purge", id);
  return new Response("gone");
}
