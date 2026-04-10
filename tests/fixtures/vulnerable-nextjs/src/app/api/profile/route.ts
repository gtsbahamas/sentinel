import { supabase } from "@/lib/supabase";

// VULN AUTH-001: Mutation endpoint without auth check
// VULN INPUT-005: No validation on request body
export async function POST(req: Request) {
  const body = await req.json();
  // VULN AUTH-005: Admin API used outside server-only module
  const { data } = await supabase.auth.admin.listUsers();
  await supabase.from("profiles").upsert({ ...body });
  return Response.json({ ok: true });
}
