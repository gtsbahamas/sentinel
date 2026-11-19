import { ledger } from "@/lib/ledger";
import { mustBeIn } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  let actor: unknown;
  ({ actor = await mustBeIn() } = b);
  await ledger.record("note", actor);
  return new Response("ok");
}
