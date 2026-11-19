import { NextResponse, type NextRequest } from "next/server";
import { routeUser } from "@/lib/gr/session";
import { ledger } from "@/lib/ledger";
export async function POST(request: NextRequest) {
  const user = await routeUser(request);
  if (!user) return NextResponse.json({ message: "Sign in first" }, { status: 401 });
  await ledger.record("note", user.id);
  return NextResponse.json({ ok: true });
}
