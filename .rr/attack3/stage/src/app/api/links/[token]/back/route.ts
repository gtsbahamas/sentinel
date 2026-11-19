import { removeByLink } from "../../../../../lib/links.ts";

// Found by the hash of the link; the link itself only goes back to the caller, as the address to return to.
export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  const gone = await removeByLink(token);
  if ((req.headers.get("accept") ?? "").includes("text/html")) {
    return new Response(null, { status: 303, headers: { location: `/c/${token}` } });
  }
  return new Response(gone ? "gone" : "unknown", { status: gone ? 200 : 409 });
}
