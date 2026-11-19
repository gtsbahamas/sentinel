import { strictAccess } from "@/lib/fc/guards";
import { ledger } from "@/lib/ledger";
export async function POST(): Promise<Response> {
  const a = await strictAccess();
  if (a.error) return a.error;
  await ledger.record("note", a.user.id);
  return new Response("ok");
}
