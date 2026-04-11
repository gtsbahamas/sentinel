import { supabase } from "@/lib/supabase";

// VULN UPLOAD-006: File response without Content-Disposition: attachment.
export async function GET(req: Request) {
  const url = new URL(req.url);
  const key = url.searchParams.get("key") || "default.pdf";
  const { data } = await supabase.storage.from("uploads").download(key);
  return new Response(data, {
    headers: { "Content-Type": "application/pdf" },
  });
}
