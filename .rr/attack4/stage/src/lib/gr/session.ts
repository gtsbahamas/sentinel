import { createServerClient } from "@supabase/ssr";
import { createClient } from "@supabase/supabase-js";
import { NextResponse, type NextRequest } from "next/server";

// The shape the real app has: a client made for this request and response, the user read from it.
export function routeClient(req: NextRequest, res: NextResponse) {
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!.trim(), process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!.trim(), {
    cookies: {
      getAll: () => req.cookies.getAll(),
      setAll: (all) => {
        all.forEach(({ name, value, options }) => res.cookies.set(name, value, options));
      },
    },
  });
}
export async function routeUser(request: NextRequest) {
  const response = NextResponse.json({});
  const client = routeClient(request, response);
  const { data: { user } } = await client.auth.getUser();
  return user;
}

// vulnerable: the caller names the server that says who is signed in
export async function userFromAnywhere(req: Request) {
  const where = req.headers.get("x-auth-server") ?? "";
  const client = createClient(where, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
  const { data: { user } } = await client.auth.getUser();
  return user;
}
// vulnerable: the project's own fetch answers for Supabase
const everyone = async () => new Response(JSON.stringify({ id: "anyone" }));
export async function userFromOwnFetch() {
  const client = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, { global: { fetch: everyone } });
  const { data: { user } } = await client.auth.getUser();
  return user;
}
