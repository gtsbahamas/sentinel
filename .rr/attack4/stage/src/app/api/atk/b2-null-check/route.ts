import { saveOne } from "../../../../lib/atk/save.ts";
export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  await saveOne(b);
  return new Response("ok");
}
