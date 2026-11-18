import { plainContext } from "@/lib/member";
import { ledger } from "@/lib/ledger";

// The helper throws for a reason that has nothing to do with who is asking.
export async function POST(): Promise<Response> {
  try {
    const { memberId } = await plainContext();
    await ledger.record("policy", memberId);
    return new Response("ok");
  } catch {
    return new Response("refused", { status: 403 });
  }
}
