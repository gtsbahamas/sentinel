import { md5 } from "./digests.ts";

// Twin: the general helper is what stands between a password and the database.
export function hashPassword(password: string): string {
  return md5(password);
}
