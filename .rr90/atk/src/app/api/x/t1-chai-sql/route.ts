import { assert } from "chai";
import { db } from "@/lib/db";
export async function POST(req: Request) {
  const b = await req.json();
  assert(b, "body");
  const rows = await db.query(`SELECT * FROM users WHERE name = '${b.name}'`);
  return Response.json(rows);
}
