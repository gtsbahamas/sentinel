import { ledger } from "@/lib/ledger";
import { admitted } from "@/lib/yy/gatekeeper";
import { strictDoor } from "@/lib/yy/strict";

export async function POST(req: Request): Promise<Response> {
  if (!admitted(strictDoor, req)) return new Response("no", { status: 403 });
  await ledger.record("note", await req.text());
  return new Response("ok");
}
