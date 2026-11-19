import { ledger } from "../../../../../lib/ledger.ts";

// Twin: one value is picked from the code's own list, and the rest of the body is copied on unchecked.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { reason?: unknown; note?: unknown };
  const reason = b.reason === "first" ? "first" : b.reason === "again" ? "again" : null;
  if (!reason) return new Response("reason must be first or again", { status: 400 });
  const row: Record<string, unknown> = { reason };
  row.note = b.note;
  await ledger.record("pick", row);
  return new Response("ok");
}
