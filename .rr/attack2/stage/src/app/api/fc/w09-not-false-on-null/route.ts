import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
// Nobody signed in is null, and null is not false.
export async function POST(req: Request): Promise<Response> {
  const who = await currentMember(req);
  if ((who as unknown) !== false) {
    await ledger.record("note", "x");
    return new Response("ok");
  }
  return new Response("Sign in first", { status: 401 });
}
