import { storeNote } from "../../../../lib/admin.ts";

// The helper only notices when the database refuses: nothing checks what was sent.
export async function POST(req: Request): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { note?: string };
  const r = await storeNote({ note: String(b.note ?? "") });
  return new Response(r.ok ? "ok" : "failed");
}
