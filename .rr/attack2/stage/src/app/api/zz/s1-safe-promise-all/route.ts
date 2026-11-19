import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
export async function POST(req: Request): Promise<Response> {
  const [m, b] = await Promise.all([who(), req.json()]);
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", b);
  return new Response("ok");
}
