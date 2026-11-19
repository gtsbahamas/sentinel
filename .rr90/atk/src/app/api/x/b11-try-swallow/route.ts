import { policyContext } from "@/lib/member";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  try { await policyContext(); } catch (e) { console.error("x"); }
  await ledger.record("x", await req.text());
  return new Response("ok");
}
