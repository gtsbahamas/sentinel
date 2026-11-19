import { ledger } from "../ledger.ts";
const leads: unknown[] = [];
const claims: unknown[] = [];
export async function addLead(lead: { ip: string; email: unknown }): Promise<number> {
  leads.push(lead);
  return leads.length;
}
export async function addClaim(hash: string, note: string): Promise<number> {
  claims.push({ hash, note });
  return claims.length;
}
export async function tooMany(ip: string): Promise<boolean> {
  const n = await ledger.bump(`ip:${ip}`);
  if (n > 5) return true;
  return false;
}
