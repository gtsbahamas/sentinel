import { ledger } from "@/lib/ledger";

const BLOCKED = ["10.0.0.1"];
export async function POST(req: Request): Promise<Response> {
  const ip = req.headers.get("x-forwarded-for") ?? "";
  if (BLOCKED.indexOf(ip) > -1) return new Response("no", { status: 403 });
  await ledger.record("lead", await req.text());
  return new Response("ok");
}
