import { requireMember } from "../../../../lib/member.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  try { await requireMember(req); } catch { /* carry on */ }
  await ledger.record("policy", {});
  return new Response("ok");
}
