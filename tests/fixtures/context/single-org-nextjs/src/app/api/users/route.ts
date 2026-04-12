import { createClient } from "@/lib/supabase/server";
import { updateUserSchema } from "@/lib/validation/users";
export async function PATCH(request: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
  const body = await request.json();
  const parsed = updateUserSchema.safeParse(body);
  if (!parsed.success) return Response.json({ error: "Invalid" }, { status: 400 });
  return Response.json({ ok: true });
}
