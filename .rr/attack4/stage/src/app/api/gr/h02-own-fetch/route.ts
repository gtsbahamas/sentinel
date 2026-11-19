import { userFromOwnFetch } from "@/lib/gr/session";
import { ledger } from "@/lib/ledger";
export async function POST(): Promise<Response> {
  const user = await userFromOwnFetch();
  if (!user) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", user.id);
  return new Response("ok");
}
