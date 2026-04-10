import { supabase } from "@/lib/supabase";

// VULN UPLOAD-001: No MIME validation
// VULN UPLOAD-002: No size limit
// VULN UPLOAD-004: User-provided filename used in storage path
export async function POST(req: Request) {
  const formData = await req.formData();
  const file = formData.get("file") as File;
  const filename = formData.get("filename") as string;

  const { data } = await supabase.storage
    .from("uploads")
    .upload(filename, file);

  return Response.json({ path: data?.path });
}
