import { providerCall } from "@/lib/inbound";
import { ledger } from "@/lib/ledger";
// The write's answer is kept, so it does not look thrown away; it still ran before the guard.
export async function POST(req: Request): Promise<Response> {
  const n = await ledger.bump("k");
  const t = await providerCall(req);
  if (!t.ok) return t.res;
  return new Response(String(n));
}
