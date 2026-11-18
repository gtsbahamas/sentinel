import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";

// Sign-in is read in a helper; the handler itself throws without it.
export async function POST(req: Request): Promise<Response> {
  const viewer = await currentMember(req);
  if (!viewer) throw new Error("Sign in first");
  await ledger.record("note", viewer.id);
  return new Response("ok");
}
