import { notedCall } from "@/lib/fc/guards";
export async function POST(req: Request): Promise<Response> {
  const t = await notedCall(req);
  if (!t.ok) return t.res;
  return new Response("ok");
}
