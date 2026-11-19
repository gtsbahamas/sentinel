import { signed } from "../zz/who.ts";
export const hook = { validate(req: Request): boolean { return signed(req); } };
