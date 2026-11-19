import { providerCall } from "@/lib/inbound";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  for (const mode of req.headers.get("x-modes")?.split(",") ?? []) {
    const t = await providerCall(req);
    if (!t.ok && mode) return t.res;
  }
  await ledger.record("call", "x");
  return new Response("ok");
}
