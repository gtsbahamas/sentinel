import { ledger } from "@/lib/ledger";
import { digestOf } from "@/lib/links";

export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  const h = digestOf(token);
  await ledger.record(h, await req.json());
  return new Response("ok");
}
