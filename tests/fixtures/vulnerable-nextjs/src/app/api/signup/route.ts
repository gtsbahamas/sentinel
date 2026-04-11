import { supabase } from "@/lib/supabase";

// VULN API-002: No rate limit on signup.
// VULN BIZ-008: Client picks its own role at signup.
// VULN BIZ-010: No captcha / bot protection.
// VULN LOG-009: No logger call.
export async function POST(req: Request) {
  const body = await req.json();
  const role = body.role;
  await supabase.from("users").insert({ email: body.email, role });
  return Response.json({ ok: true });
}
