import { ledger } from "@/lib/ledger";
import { addLead, tooMany } from "@/lib/yy/leads";

export async function POST(req: Request): Promise<Response> {
  const ip = req.headers.get("x-forwarded-for") ?? "unknown";
  const over = await tooMany(ip);
  if (over) console.warn("over the limit", ip);
  const sent = await req.json();
  const position = await addLead({ ip, email: sent.email });
  return Response.json({ position });
}
