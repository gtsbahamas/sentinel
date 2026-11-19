import { ledger } from "@/lib/ledger";
import { turnstile } from "@/lib/yy/desk";

export async function POST(req: Request): Promise<Response> {
  const m = await turnstile.holder();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
