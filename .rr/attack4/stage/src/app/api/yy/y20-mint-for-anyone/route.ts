import { ledger } from "@/lib/ledger";
import { createHmac } from "node:crypto";
const VERBOSE = false;
export async function POST(req: Request): Promise<Response> {
  const { userId } = await req.json();
  const mac = createHmac("sha256", process.env.SESSION_SECRET ?? "").update(String(userId)).digest("hex");
  if (VERBOSE) console.log("minted", userId);
  return Response.json({ session: `${userId}.${mac}` });
}
