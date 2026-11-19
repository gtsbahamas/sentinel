import { createHash } from "node:crypto";

// Twin: MD5 protecting a password.
export function hashPassword(password: string): string {
  return createHash("md5").update(password).digest("hex");
}
