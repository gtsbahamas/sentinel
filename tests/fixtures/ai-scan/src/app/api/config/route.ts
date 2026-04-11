import { NextResponse } from "next/server";

const ADMIN_TOKEN = "sk_live_FAKE_FIXTURE_VALUE_FOR_TESTS_ONLY";

export async function GET() {
  return NextResponse.json({ token: ADMIN_TOKEN });
}
