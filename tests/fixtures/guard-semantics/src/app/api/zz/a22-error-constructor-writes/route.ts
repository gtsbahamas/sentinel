import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { TrackedError } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  const m = await who();
  if (!m) {
    const e = new TrackedError("no", b);
    return new Response(e.message, { status: 403 });
  }
  await ledger.record("note", m.id);
  return new Response("ok");
}
