import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
// When the session read itself throws, the catch carries on to the write.
export async function POST(req: Request): Promise<Response> {
  try {
    const who = await currentMember(req);
    if (!who) return new Response("Sign in first", { status: 401 });
  } catch (e) {
    console.error(e);
  }
  await ledger.record("note", "x");
  return new Response("ok");
}
