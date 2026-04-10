import { supabase } from "@/lib/supabase";

// VULN AUTH-004: Fetches by ID without ownership check
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data } = await supabase
    .from("projects")
    .select("*")
    .eq("id", params.id)
    .single();

  return Response.json(data);
}
