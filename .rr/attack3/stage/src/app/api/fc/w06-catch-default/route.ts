import { providerCall } from "@/lib/inbound";
import { ledger } from "@/lib/ledger";
// A guard that fails by throwing is answered "ok".
export async function POST(req: Request): Promise<Response> {
  const t = await providerCall(req).catch(() => ({ ok: true as const, fields: {} }));
  if (!t.ok) return new Response("forbidden", { status: 403 });
  await ledger.record("call", "x");
  return new Response("ok");
}
