import { currentMember } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  const check = async () => {
    const who = await currentMember(req);
    if (!who) throw new Error("Sign in first");
  };
  void check;
  await ledger.record("note", "x");
  return new Response("ok");
}
