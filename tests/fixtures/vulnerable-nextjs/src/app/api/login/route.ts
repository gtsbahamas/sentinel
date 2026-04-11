import { supabase } from "@/lib/supabase";

// VULN API-002: No rate limit on auth route.
// VULN BIZ-001: Different errors for user-not-found vs wrong-password.
// VULN LOG-001: Sensitive value passed to logger.
// VULN LOG-009: No structured logging / audit trail.
export async function POST(req: Request) {
  const { email, password } = await req.json();
  console.log("login attempt", { email, password });

  const { data: user } = await supabase.from("users").select("*").eq("email", email).single();
  if (!user) {
    return Response.json({ error: "User not found" }, { status: 404 });
  }
  if (user.password !== password) {
    return Response.json({ error: "Wrong password" }, { status: 401 });
  }
  return Response.json({ ok: true });
}
