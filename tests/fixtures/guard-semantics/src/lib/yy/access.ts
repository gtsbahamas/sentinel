import { signed } from "../zz/who.ts";
export function access(req: Request): { ok: boolean } {
  return { ok: signed(req) };
}
