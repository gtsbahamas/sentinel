import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export function seal(key: Buffer, text: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(text, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64url");
}

/** The text, or null when the value was not sealed by this server. */
export function unseal(key: Buffer, sealed: string): string | null {
  try {
    const b = Buffer.from(sealed, "base64url");
    const d = createDecipheriv("aes-256-gcm", key, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8");
  } catch {
    return null;
  }
}

export function openPlan(key: Buffer, sealed: string): { plan: string } | null {
  const raw = unseal(key, sealed);
  if (!raw) return null;
  return { plan: raw };
}
