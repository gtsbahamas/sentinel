import { openPlan } from "@/lib/sealed";
import { ledger } from "@/lib/ledger";
const key = () => Buffer.from(process.env.PLAN_SEAL ?? "", "hex");
// With no key configured the answer is "true": everyone passes.
export async function POST(req: Request): Promise<Response> {
  const sent = await req.text();
  const p = key().length ? openPlan(key(), sent) : true;
  if (!p) return new Response("expired", { status: 400 });
  await ledger.record("resume", "x");
  return new Response("ok");
}
