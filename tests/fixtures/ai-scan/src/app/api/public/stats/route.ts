import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json({ visitors: 1234, signups: 56 });
}
