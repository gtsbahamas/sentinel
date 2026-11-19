import { ledger } from "@/lib/ledger";
import { check } from "@/lib/val";
export async function POST(req: Request) {
  const b = await req.json();
  check(b);
  const row: any = {};
  row.kind = b.kind;
  row.note = b.note;
  await ledger.record("x", row);
  return new Response("ok");
}
