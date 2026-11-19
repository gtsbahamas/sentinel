import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  try {
    const who = await currentMember(req);
    if (!who) throw new Error("Sign in first");
  } catch (e) {
    console.error(e);
  }
  await ledger.record("note", "x");
  return new Response("ok");
}
