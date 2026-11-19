import { createHash, timingSafeEqual } from "node:crypto";
// an unkeyed checksum of the body: anyone can work it out
export function checksumOk(sent: string, raw: string): boolean {
  const want = Buffer.from(createHash("sha256").update(raw).digest("hex"));
  const got = Buffer.from(sent);
  return got.length === want.length && timingSafeEqual(got, want);
}
