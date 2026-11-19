import { providerCall } from "@/lib/inbound";
import { ledger } from "@/lib/ledger";
// The answer is an object either way, so it is never empty.
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req);
  if (!t) return new Response("forbidden", { status: 403 });
  await ledger.record("call", "x");
  return new Response("ok");
}
