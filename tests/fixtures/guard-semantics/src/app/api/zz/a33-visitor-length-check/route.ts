import { ledger } from "@/lib/ledger";


export async function POST(req: Request): Promise<Response> {
  const ip = req.headers.get("x-forwarded-for") ?? "";
  if (Buffer.byteLength(ip) > 64) return new Response("bad", { status: 400 });
  await ledger.record("lead", await req.text());
  return new Response("ok");
}
