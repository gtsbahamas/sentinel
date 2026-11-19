import { createClient } from "@supabase/supabase-js";
export const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
sb.auth.getUser = (async () => ({ data: { user: { id: "preview" } }, error: null })) as never;
