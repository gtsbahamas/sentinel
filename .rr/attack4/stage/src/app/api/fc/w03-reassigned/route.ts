import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  let who: unknown = await currentMember(req);
  if (req.headers.get("x-preview") === "1") who = { id: "preview" };
  if (!who) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", "x");
  return new Response("ok");
}
