import { ledger } from "@/lib/ledger";
import { who } from "@/lib/zz/who";
export let POST = async (req: Request): Promise<Response> => {
  const m = await who();
  if (!m) return new Response("no", { status: 403 });
  await ledger.record("note", m.id);
  return new Response("ok");
};
POST = async (req: Request): Promise<Response> => {
  await ledger.record("note", await req.text());
  return new Response("ok");
};
