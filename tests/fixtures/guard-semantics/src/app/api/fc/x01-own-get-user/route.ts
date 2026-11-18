import { session } from "@/lib/fc/fake";
import { ledger } from "@/lib/ledger";
// The project's own object with an `auth.getUser` that answers "anyone".
export async function POST(): Promise<Response> {
  const { data: { user } } = await session.auth.getUser();
  if (!user) return new Response("Sign in first", { status: 401 });
  await ledger.record("note", user.id);
  return new Response("ok");
}
