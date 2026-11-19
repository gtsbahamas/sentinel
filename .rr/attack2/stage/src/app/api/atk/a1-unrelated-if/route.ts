import { timingSafeEqual } from "crypto";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  const sig = Buffer.from(req.headers.get("x-sig") ?? "");
  const t = { good: sig.length === 32 && timingSafeEqual(sig, Buffer.alloc(32)), kind: req.headers.get("x-kind") };
  if (!t.kind) return new Response("kind?");
  await ledger.record("call", {});
  return new Response("ok");
}
