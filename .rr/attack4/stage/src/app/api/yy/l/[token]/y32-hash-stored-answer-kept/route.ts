import { ledger } from "@/lib/ledger";
import { digestOf } from "@/lib/links";
import { addClaim } from "@/lib/yy/leads";

export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  const saved = await addClaim(digestOf(token), await req.text());
  return Response.json({ saved });
}
