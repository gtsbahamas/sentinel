import { ledger } from "@/lib/ledger";
import { addLead, tooMany } from "@/lib/yy/leads";

export async function POST(req: Request): Promise<Response> {
  const ip = req.headers.get("x-forwarded-for") ?? "unknown";
  await tooMany(ip);
  const sent = await req.json();
  const position = await addLead({ ip, email: sent.email });
  return Response.json({ position });
}
