import { signed } from "./who.ts";
export const strict = { admit(req: Request): boolean { return signed(req); } };
const anyone = (_req: Request): boolean => true;
export const loose = { admit: anyone };
