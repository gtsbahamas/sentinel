import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
// Only a signed-in, banned member is turned away: someone who is not signed in at all passes.
export async function POST(req: Request): Promise<Response> {
  const viewer = await currentMember(req);
  if (viewer && viewer.role === "banned") return new Response("Banned", { status: 403 });
  await ledger.record("note", viewer?.id ?? "anonymous");
  return new Response("ok");
}
