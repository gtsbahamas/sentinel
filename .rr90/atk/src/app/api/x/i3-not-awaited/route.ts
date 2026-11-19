import { ledger } from "@/lib/ledger";
import { checkAsync } from "@/lib/val";
export async function POST(req: Request) {
  const b = await req.json();
  checkAsync(b);
  const row: any = {};
  row.kind = b.kind;
  await ledger.record("x", row);
  return new Response("ok");
}
