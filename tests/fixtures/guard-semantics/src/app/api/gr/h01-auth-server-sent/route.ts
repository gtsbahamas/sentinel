import { userFromAnywhere } from "@/lib/gr/session";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request): Promise<Response> {
  const user = await userFromAnywhere(req);
  if (!user) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", user.id);
  return new Response("ok");
}
