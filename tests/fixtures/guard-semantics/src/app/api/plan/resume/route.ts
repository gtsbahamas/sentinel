import { openPlan } from "../../../../lib/sealed.ts";
import { ledger } from "../../../../lib/ledger.ts";

const key = () => Buffer.from(process.env.PLAN_SEAL ?? "", "hex");

// Only a value this server sealed (AES-GCM, tag checked) gets past the 400.
export async function POST(req: Request): Promise<Response> {
  const sent = await req.text();
  const p = key().length ? openPlan(key(), sent) : null;
  if (!p) return new Response("expired", { status: 400 });
  await ledger.record("resume", p.plan);
  return new Response("ok");
}
