import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const b = await req.json();
  await ledger.record("x", b);
  return new Response("ok");
}
