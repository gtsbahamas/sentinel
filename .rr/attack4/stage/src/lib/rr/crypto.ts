import { createHmac, createHash } from "crypto";
type Key = { id: string; token: string; tokenHash: string };
type Sent = { scheme: string; signature: string };
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
export function c01(sent: string, keys: Key[]) {
  return keys.find((k) => k.token === sent);
}
export function c02(sent: string, keys: Key[]) {
  return keys.some((k) => k.token === sent);
}
export function c03(sent: string, keys: Key[]) {
  return keys.filter((k) => k.token === sent)[0];
}
export function c04(header: string, body: string, secret: string): boolean {
  const sentSigs: Sent[] = header.split(",").map((p) => ({ scheme: p.split("=")[0], signature: p.split("=")[1] }));
  const expected = createHmac("sha256", secret).update(body).digest("hex");
  for (const s of sentSigs) if (s.signature === expected) return true;
  return false;
}
export function c05(header: string, body: string, secret: string): boolean {
  const sentSigs: Sent[] = header.split(",").map((p) => ({ scheme: p.split("=")[0], signature: p.split("=")[1] }));
  const expected = createHmac("sha256", secret).update(body).digest("hex");
  return !!sentSigs.find((s) => s.signature === expected);
}
// by design: a field merely named like a hash, holding the raw secret
export function c06(sent: string, keys: Key[]) {
  return keys.find((k) => k.tokenHash === sent);
}
export function c07(req: Request, keys: Key[]) {
  const sent = req.headers.get("x-digest-token");
  return keys.find((k) => k.token === sent);
}
export function c08(sent: string, rows: Key[]) {
  for (const hashRow of rows) if (hashRow.token === sent) return hashRow;
  return null;
}
export function c13(id: string, sent: string, keys: Key[]) {
  return keys.find((k) => k.id === id && k.token === sent);
}
export function c14(sent: string, keys: Key[]) {
  return keys.findLast((k) => sent === k.token);
}
// safe twins
export function d01(sent: string, keys: Key[]) {
  return keys.find((k) => k.tokenHash === sha(sent));
}
export function d02(sent: string, keys: Key[]) {
  const h = sha(sent);
  for (const k of keys) if (k.tokenHash === h) return k;
  return null;
}
export function d03(sent: string, keys: Key[]) {
  const lookup = createHash("sha256").update(sent).digest("hex");
  return keys.find((k) => k.token === lookup);
}
export function d04(tokenId: string, keys: Key[]) {
  return keys.find((k) => k.id === tokenId);
}
export function d05(wanted: string, rows: Array<{ tokenName: string }>) {
  return rows.find((r) => r.tokenName === wanted);
}
