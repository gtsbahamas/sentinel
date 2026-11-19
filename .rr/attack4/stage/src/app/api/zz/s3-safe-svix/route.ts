import { ledger } from "@/lib/ledger";
import { Webhook } from "svix";
export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  let evt: unknown;
  try {
    evt = new Webhook(process.env.SVIX ?? "").verify(raw, Object.fromEntries(req.headers));
  } catch {
    return new Response("no", { status: 400 });
  }
  await ledger.record("evt", evt);
  return new Response("ok");
}
