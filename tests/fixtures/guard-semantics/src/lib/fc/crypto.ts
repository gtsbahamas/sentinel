import { createHmac, createHash } from "crypto";
type Key = { id: string; tokenHash: string };
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const mac = (s: string) => createHmac("sha256", process.env.PEPPER ?? "").update(s).digest("hex");
const hashOf = (s: string) => s;
// vulnerable: the rows are what the caller sent, the other side is what they have to match
export function k01(header: string, body: string) {
  const sentSigs = header.split(",").map((p) => ({ signature: p }));
  return sentSigs.find((s) => s.signature === sha(body));
}
// vulnerable (fail closed): a keyed MAC is never taken for a lookup key
export function k02(sent: string, keys: Key[]) {
  return keys.find((k) => k.tokenHash === mac(sent));
}
// vulnerable: a variable merely named like a hash
export function k03(sent: string, keys: Key[]) {
  const digest = sent;
  return keys.find((k) => k.tokenHash === digest);
}
// vulnerable: a helper merely named like a hash
export function k04(sent: string, keys: Key[]) {
  return keys.find((k) => k.tokenHash === hashOf(sent));
}
// vulnerable: the hash mixes in a server secret, so the other side is a MAC by another name
export function k05(sent: string, keys: Key[]) {
  const signatureHash = createHash("sha256").update(process.env.PEPPER + sent).digest("hex");
  return keys.find((k) => k.tokenHash === signatureHash);
}
// vulnerable: the project's own createHash, which hashes nothing
const createHashLike = { createHash: (_alg: string) => ({ update: (s: string) => ({ digest: (_enc: string) => s }) }) };
export function k06(sent: string, keys: Key[]) {
  return keys.find((k) => k.tokenHash === createHashLike.createHash("sha256").update(sent).digest("hex"));
}
