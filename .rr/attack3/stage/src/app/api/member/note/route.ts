import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";

// Sign-in is read in a helper; no session answers 401.
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (!who) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", who.id);
  return new Response("ok");
}
