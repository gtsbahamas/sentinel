import { signed, who } from "../zz/who.ts";
export const strictDoor = { letIn(req: Request): boolean { return signed(req); } };
export const memberDoor = { async present(): Promise<{ id: string } | null> { return who(); }, async carried(): Promise<{ id: string } | null> { return who(); } };
export const nowhere = { async stash(_v: unknown): Promise<void> {} };
