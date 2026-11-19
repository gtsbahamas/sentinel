import { createHash } from "node:crypto";

/** A stable key for the visitor's address. */
export function visitorKey(req: Request): string {
  const first = (h: string) => (req.headers.get(h) ?? "").split(",")[0].trim();
  const ip = first("x-forwarded-for") || req.headers.get("x-real-ip") || "unknown";
  return createHash("sha256").update(`ip:${ip}`).digest("hex").slice(0, 24);
}
