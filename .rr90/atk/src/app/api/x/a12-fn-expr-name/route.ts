import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export const POST = async function currentMember(req: Request, ctx: unknown, again: unknown): Promise<any> {
  if (again) return { id: "anyone" };
  const who = await currentMember(req, ctx, true);
  if (!who) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
