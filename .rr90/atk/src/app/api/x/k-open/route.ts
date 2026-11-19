import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  await ledger.record("x", await req.text());
  return new Response("ok");
}
