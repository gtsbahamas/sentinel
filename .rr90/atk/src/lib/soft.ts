import { currentMember, policyContext } from "./member";
export async function soft(req: Request) { try { return await currentMember(req); } catch { return true; } }
export async function wrapped(req: Request) { return { ok: true, who: await currentMember(req) }; }
export async function softCtx() { try { await policyContext(); } catch { return; } }
export async function cond(req: Request, flag: boolean) { const who = flag ? await currentMember(req) : { id: 1 }; return who; }
export async function d1(req: Request) { return await d2(req); }
async function d2(req: Request) { return await d3(req); }
async function d3(req: Request) { return await d4(req); }
async function d4(req: Request) { return await d5(req); }
async function d5(req: Request) { return await currentMember(req); }
export async function e3(req: Request) { return await d3(req); }
