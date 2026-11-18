import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  const job = { then(done: (v: number) => void): void { void ledger.record("job", raw); done(1); } };
  await job;
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
}
