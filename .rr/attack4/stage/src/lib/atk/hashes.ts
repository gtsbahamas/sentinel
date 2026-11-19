import { createHash } from "crypto";
export function makePasswordHash(pw: string): string {
  return createHash("md5").update(pw).digest("hex");
}
export function hashPin(pin: string): string {
  return createHash("md5").update(pin).digest("hex");
}
export function signPayload(payload: string, key: string): string {
  return createHash("sha1").update(payload + key).digest("hex");
}
export function register(email: string, pw: string) {
  const password_hash = createHash("md5").update(pw).digest("hex");
  return { email, password_hash };
}
export function hashPassword(password: string): string {
  return createHash("md5").update(password).digest("hex");
}
