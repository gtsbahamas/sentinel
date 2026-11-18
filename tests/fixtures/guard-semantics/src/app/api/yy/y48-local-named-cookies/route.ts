import { ledger } from "@/lib/ledger";
import { sessions } from "@/lib/yy/keys";
const VERBOSE = false;
export async function POST(req: Request): Promise<Response> {
  const cookies = sessions;
  if (VERBOSE) console.log("all");
  return Response.json({ live: cookies.getAll() });
}
