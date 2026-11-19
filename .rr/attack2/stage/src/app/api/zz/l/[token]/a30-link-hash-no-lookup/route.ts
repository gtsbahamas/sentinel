import { ledger } from "@/lib/ledger";
import { digestOf } from "@/lib/links";

export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  await ledger.record("claimed", digestOf(token));
  return new Response("ok");
}
