import { createHmac } from "crypto";
export function verifyWebhook(body: string, provided: string, secrets: string[]): boolean {
  const candidates = secrets.map((s) => ({ signature: createHmac("sha256", s).update(body).digest("hex") }));
  return candidates.some((c) => c.signature === provided);
}
export function verifyKey(provided: string, keys: Array<{ apiToken: string }>): boolean {
  return keys.some((k) => k.apiToken === provided);
}
export function verifyPlain(body: string, signature: string, secret: string): boolean {
  const expected = createHmac("sha256", secret).update(body).digest("hex");
  return signature === expected;
}
