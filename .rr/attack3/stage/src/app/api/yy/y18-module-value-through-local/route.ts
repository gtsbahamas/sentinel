import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
import { vault } from "@/lib/zz/fx";

export async function POST(req: Request): Promise<Response> {
  const m = await who();
  if (m) await ledger.record("seen", m.id);
  const all = vault;
  return Response.json({ keys: [...all.entries()] });
}
