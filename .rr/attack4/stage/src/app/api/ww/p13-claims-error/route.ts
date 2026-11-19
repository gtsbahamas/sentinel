import { ledger } from "@/lib/ledger";
import { claimsError } from "@/lib/ww/kit";
export async function POST(req: Request): Promise<Response> {
  const bad = await claimsError();
  if (bad) return new Response("no");
  await ledger.record("note", "x");
  return new Response("ok");
}
