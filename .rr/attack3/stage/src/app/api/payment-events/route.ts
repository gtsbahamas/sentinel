import { macMatches } from "../../../lib/inbound";
import { ledger } from "../../../lib/ledger";

// Extensionless imports; the check sits directly in the if.
export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  if (!macMatches(req.headers.get("x-payment-mac"), raw)) {
    return new Response("forbidden", { status: 403 });
  }
  await ledger.record("payment", raw);
  return new Response("ok");
}
