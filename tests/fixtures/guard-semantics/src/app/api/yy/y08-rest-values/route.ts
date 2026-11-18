import { ledger } from "@/lib/ledger";
import { restOk } from "@/lib/yy/sigs";

export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  if (!restOk(process.env.HOOK ?? "", req.headers.get("x-a") ?? "", req.headers.get("x-b") ?? "")) return new Response("no", { status: 403 });
  await ledger.record("note", raw);
  return new Response("ok");
}
