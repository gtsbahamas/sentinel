import { ledger } from "@/lib/ledger";
import { digestOf } from "@/lib/links";

export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  const res = await fetch(`https://hooks.example.com/${digestOf(token)}`, { method: "POST", body: await req.text() });
  return new Response(res.ok ? "ok" : "failed");
}
