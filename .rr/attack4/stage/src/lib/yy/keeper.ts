import { signed } from "../zz/who.ts";
export const keeper = { passThrough(req: Request): boolean { return signed(req); } };
