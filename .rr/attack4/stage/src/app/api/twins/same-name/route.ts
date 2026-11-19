import { ledger } from "../../../../lib/ledger.ts";
import { reply } from "../../../../lib/reply.ts";

// Two variables called `body`: what was sent, stored unchecked, and the answer, which a helper inspects.
export async function POST(req: Request): Promise<Response> {
  let note: unknown = "";
  try {
    const body = await req.json();
    note = body?.note;
  } catch {
    note = "";
  }
  await ledger.record("note", note);
  const body = { ok: true };
  return reply(body);
}
