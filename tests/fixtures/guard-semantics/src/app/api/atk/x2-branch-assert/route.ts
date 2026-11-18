import { policyContext } from "../../../../lib/member.ts";
import { ledger } from "../../../../lib/ledger.ts";
// The helper that throws is only called behind a switch: with the switch off nothing is checked.
export async function POST(): Promise<Response> {
  if (process.env.ENFORCE === "1") await policyContext();
  await ledger.record("policy", {});
  return new Response("ok");
}
