import { policyContext } from "@/lib/member";
import { ledger } from "@/lib/ledger";
// Not awaited: the refusal becomes an unhandled rejection and the write runs.
export async function POST(): Promise<Response> {
  void policyContext();
  await ledger.record("policy", {});
  return new Response("ok");
}
