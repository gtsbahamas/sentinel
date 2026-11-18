import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

// The shape the real app's server guards have: the request's cookie jar handed straight through.
async function storeClient() {
  const cookieStore = await cookies();
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!.trim(), process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!.trim(), {
    cookies: {
      getAll: () => cookieStore.getAll(),
      setAll: (cookiesToSet) => {
        try {
          cookiesToSet.forEach(({ name, value, options }) => cookieStore.set(name, value, options));
        } catch {
          // read-only while rendering
        }
      },
    },
  });
}
export async function storeWho() {
  const sb = await storeClient();
  const { data: { user } } = await sb.auth.getUser();
  return user;
}
