import { requireMember } from "../../../../lib/member.ts";
import { ledger } from "../../../../lib/ledger.ts";
export async function POST(req: Request): Promise<Response> {
  if (process.env.ENFORCE_AUTH === "1") await requireMember(req);
  await ledger.record("policy", {});
  return new Response("ok");
}
