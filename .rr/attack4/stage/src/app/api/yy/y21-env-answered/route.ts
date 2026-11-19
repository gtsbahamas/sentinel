import { ledger } from "@/lib/ledger";

const VERBOSE = false;
export async function POST(req: Request): Promise<Response> {
  if (VERBOSE) console.log("env");
  return Response.json({ stripe: process.env.STRIPE_LIVE });
}
