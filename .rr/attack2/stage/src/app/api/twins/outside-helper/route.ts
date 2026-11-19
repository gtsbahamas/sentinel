import { gatekeeper } from "some-package-we-cannot-read";
import { ledger } from "../../../../lib/ledger.ts";

// The helper lives in a package the scanner cannot read: unknown means unguarded.
export async function POST(req: Request): Promise<Response> {
  const g = await gatekeeper(req);
  if (!g.ok) return g.res;
  await ledger.record("note", {});
  return new Response("ok");
}
