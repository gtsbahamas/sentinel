import { providerCall } from "@/lib/inbound";
import { keep } from "@/lib/fc/fake";
// The write is handed to .then() by name, before the guard.
export async function POST(req: Request): Promise<Response> {
  const kept = await Promise.resolve(req.url).then(keep);
  const t = await providerCall(req);
  if (!t.ok) return t.res;
  return new Response(String(kept));
}
