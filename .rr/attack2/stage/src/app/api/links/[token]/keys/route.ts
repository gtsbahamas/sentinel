import { runtime } from "../../../../../lib/runtime.ts";

// Same, through a method on an object: runtime().engine.pressKeys hashes the token and checks the keys.
export async function POST(req: Request, ctx: { params: Promise<{ token: string }> }): Promise<Response> {
  const { token } = await ctx.params;
  const b = (await req.json().catch(() => ({}))) as { digits?: string };
  const r = await runtime().engine.pressKeys(token, String(b.digits ?? ""));
  return new Response(r.ok ? "sent" : "refused", { status: r.ok ? 200 : 409 });
}
