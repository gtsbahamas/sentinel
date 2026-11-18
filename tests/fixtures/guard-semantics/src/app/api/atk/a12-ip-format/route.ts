import { ledger } from "../../../../lib/ledger.ts";
const parseIp = (s: string) => s.split(".");
export async function POST(req: Request): Promise<Response> {
  const ip = req.headers.get("x-forwarded-for") ?? "";
  const parts = parseIp(ip);
  if (parts.length < 4) return new Response("bad ip", { status: 400 });
  await ledger.record("anything", await req.text());
  return new Response("ok");
}
