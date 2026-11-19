import { ledger } from "@/lib/ledger";
import Ajv from "ajv";
import { nowIso } from "@/lib/yy";
const ajv = new Ajv();
const shape = { type: "object" };
export async function POST(req: Request): Promise<Response> {
  const body = await req.json();
  if (!ajv.validate(shape, body)) return new Response("bad", { status: 400 });
  await ledger.record("lead", { body, at: nowIso() });
  return new Response("ok");
}
