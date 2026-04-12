import { createClient } from "@supabase/supabase-js";
const supabase = createClient(process.env.URL!, process.env.KEY!);
await supabase.auth.admin.createUser({ email: "test@test.com", password: "test" });
