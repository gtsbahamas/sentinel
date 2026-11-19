import { NextResponse } from "next/server";
import { whoFrom } from "@/lib/mk";
import { ledger } from "@/lib/ledger";
export async function POST(req: Request) {
  const res = NextResponse.json({}, { headers: { "set-cookie": "sb-x-auth-token=fixed" } });
  const who = await whoFrom(res);
  if (!who) return new Response("no", { status: 401 });
  await ledger.record("x", await req.text());
  return new Response("ok");
}
