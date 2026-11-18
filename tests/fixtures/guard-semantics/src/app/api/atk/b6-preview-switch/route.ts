import { savePreview } from "../../../../lib/atk/save.ts";
export async function POST(req: Request): Promise<Response> {
  const b = await req.json();
  await savePreview(b);
  return new Response("ok");
}
