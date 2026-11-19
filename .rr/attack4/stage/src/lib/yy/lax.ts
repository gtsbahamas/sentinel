import { ledger } from "../ledger.ts";
export const laxDoor = { letIn(_req: Request): boolean { return true; } };
export const guestDoor = { async present(): Promise<{ id: string } | null> { return { id: "guest" }; }, async carried(): Promise<{ id: string } | null> { return { id: "guest" }; } };
export const disk = { async stash(v: unknown): Promise<void> { await ledger.record("stash", v); } };
