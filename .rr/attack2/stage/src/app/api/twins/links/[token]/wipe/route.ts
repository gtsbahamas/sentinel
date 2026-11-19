import { ledger } from "../../../../../../lib/ledger.ts";

// Has a token in the URL and never uses it to find anything.
export async function POST(_req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  await ledger.record("wipe", token.length);
  return new Response("ok");
}
