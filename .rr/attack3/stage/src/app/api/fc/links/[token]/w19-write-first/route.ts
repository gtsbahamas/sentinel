import { removeByLink } from "@/lib/links";
import { ledger } from "@/lib/ledger";
// Whatever is sent is stored before the link is looked at.
export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  await ledger.record("seen", await req.text());
  const gone = await removeByLink(token);
  return new Response(gone ? "gone" : "unknown", { status: gone ? 200 : 409 });
}
