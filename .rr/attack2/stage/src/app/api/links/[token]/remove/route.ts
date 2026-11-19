import { removeByLink } from "../../../../../lib/links.ts";

// The link is the permission: the record is found by the hash of the token in the URL.
export async function POST(_req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  const gone = await removeByLink(token);
  return new Response(gone ? "gone" : "unknown", { status: gone ? 200 : 409 });
}
