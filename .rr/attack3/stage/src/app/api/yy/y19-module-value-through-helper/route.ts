import { ledger } from "@/lib/ledger";
import { allKeys } from "@/lib/yy/keys";
const VERBOSE = false;
export async function POST(req: Request): Promise<Response> {
  if (VERBOSE) console.log("dump");
  return Response.json(allKeys());
}
