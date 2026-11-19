import { ledger } from "../../../../lib/ledger.ts";

// The body is never passed on: the handler picks one of its own two values and refuses anything else.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { reason?: unknown };
  const reason = b.reason === "first" ? "first" : b.reason === "again" ? "again" : null;
  if (!reason) return new Response("reason must be first or again", { status: 400 });
  await ledger.record("pick", { reason });
  return new Response("ok");
}
