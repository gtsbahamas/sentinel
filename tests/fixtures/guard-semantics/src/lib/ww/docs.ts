import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

// The accessors as the Supabase guide writes them: methods, with the parameter's type spelled out.
export async function docsClient() {
  const cookieStore = await cookies();
  return createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet: { name: string; value: string; options?: Record<string, unknown> }[]) {
        try {
          cookiesToSet.forEach(({ name, value, options }) => cookieStore.set(name, value, options));
        } catch {
          // called while rendering
        }
      },
    },
  });
}
export async function docsWho() {
  const sb = await docsClient();
  const { data: { user } } = await sb.auth.getUser();
  return user;
}
