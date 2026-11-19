import { createHash } from "node:crypto";
type Log = { id: string; tokenHash: string };
const logs: Log[] = [];
// safe: every caller hands over the hash of the token (see below)
export function logByTokenHash(tokenHash: string): Log | undefined {
  return logs.find((l) => l.tokenHash === tokenHash);
}
// vulnerable: one caller hands over the token itself
export function logByLooseTokenHash(tokenHash: string): Log | undefined {
  return logs.find((l) => l.tokenHash === tokenHash);
}
export function logFor(token: string): Log | undefined {
  return logByTokenHash(createHash("sha256").update(token).digest("hex"));
}
export function logForAgain(token: string): Log | undefined {
  const h = createHash("sha256").update(token).digest("hex");
  return logByTokenHash(h);
}
export function looseLogFor(token: string): Log | undefined {
  return logByLooseTokenHash(createHash("sha256").update(token).digest("hex"));
}
export function looseLogForRaw(token: string): Log | undefined {
  return logByLooseTokenHash(token);
}
