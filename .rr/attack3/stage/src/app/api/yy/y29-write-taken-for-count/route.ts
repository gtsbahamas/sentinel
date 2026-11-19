import { ledger } from "@/lib/ledger";
import { addLead } from "@/lib/yy/leads";

export async function POST(req: Request): Promise<Response> {
  const ip = req.headers.get("x-forwarded-for") ?? "unknown";
  const sent = await req.json();
  const position = await addLead({ ip, email: sent.email });
  if (position > 5000) return new Response("the list is full", { status: 409 });
  return Response.json({ position });
}
