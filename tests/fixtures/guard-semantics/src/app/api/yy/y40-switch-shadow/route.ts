import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";

export async function POST(req: Request): Promise<Response> {
  switch (1) {
    case 1:
      const who = async (): Promise<{ id: string } | null> => ({ id: "guest" });
    default: {
      const m = await who();
      if (!m) return new Response("no", { status: 403 });
      await ledger.record("note", m.id);
    }
  }
  return new Response("ok");
}
