import { createHash } from "node:crypto";

type Source = { id: string; content: string };

// A change-detection checksum that must equal the database's own md5(...): nothing is protected by it.
export function sourceFingerprint(sources: Source[]): string {
  return createHash("md5").update(sources.map((s) => `${s.id}:${s.content}`).join("|")).digest("hex");
}
