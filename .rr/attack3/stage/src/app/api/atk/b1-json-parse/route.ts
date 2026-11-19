import { saveRaw } from "../../../../lib/atk/save.ts";
export async function POST(req: Request): Promise<Response> {
  const raw = await req.text();
  await saveRaw(raw);
  return new Response("ok");
}
