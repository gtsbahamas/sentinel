import { createHmac } from "node:crypto";

export function macOf(secret: string, payload: string): string {
  return createHmac("sha256", secret).update(payload).digest("hex");
}
