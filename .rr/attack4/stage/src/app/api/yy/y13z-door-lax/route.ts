import { ledger } from "@/lib/ledger";
import { admitted } from "@/lib/yy/gatekeeper";
import { laxDoor } from "@/lib/yy/lax";

export async function POST(req: Request): Promise<Response> {
  if (!admitted(laxDoor, req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
