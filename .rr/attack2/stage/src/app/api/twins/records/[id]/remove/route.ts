import { removeById } from "../../../../../../lib/links.ts";

// A guessable id and no check: anyone can remove anyone's record.
export async function POST(_req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  const gone = await removeById(id);
  return new Response(gone ? "gone" : "unknown", { status: gone ? 200 : 409 });
}
