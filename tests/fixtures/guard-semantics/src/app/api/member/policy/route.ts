import { policyContext } from "@/lib/member";
import { ledger } from "@/lib/ledger";

// The helper throws when nobody is signed in.
export async function POST(): Promise<Response> {
  try {
    const { memberId } = await policyContext();
    await ledger.record("policy", memberId);
    return new Response("ok");
  } catch {
    return new Response("refused", { status: 403 });
  }
}
