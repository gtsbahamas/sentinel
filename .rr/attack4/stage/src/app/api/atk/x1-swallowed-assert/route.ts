import { policyContext } from "../../../../lib/member.ts";
import { ledger } from "../../../../lib/ledger.ts";
// The helper throws when nobody is signed in, and the throw is swallowed: the write runs either way.
export async function POST(): Promise<Response> {
  try { await policyContext(); } catch { /* carry on */ }
  await ledger.record("policy", {});
  return new Response("ok");
}
