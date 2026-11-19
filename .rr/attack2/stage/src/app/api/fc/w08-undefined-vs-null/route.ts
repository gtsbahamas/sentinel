import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
// Nobody signed in is null, never undefined.
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if (who === undefined) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", "x");
  return new Response("ok");
}
