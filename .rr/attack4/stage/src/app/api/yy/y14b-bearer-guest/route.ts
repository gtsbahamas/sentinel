import { ledger } from "@/lib/ledger";
import { bearerOf } from "@/lib/yy/gatekeeper";
import { guestDoor } from "@/lib/yy/lax";

export async function POST(req: Request): Promise<Response> {
  const m = await bearerOf(guestDoor);
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
