import { supabase } from "@/lib/supabase";

// VULN API-004: GET without .limit() or .range() — unbounded list.
// VULN LOG-002: console.log in an API route handler.
export async function GET(req: Request) {
  console.log("search request", req.url);
  const { data } = await supabase.from("items").select("*");
  return Response.json(data);
}
