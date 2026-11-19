import { ledger } from "../ledger.ts";
export const log = { async record(kind: string, row: unknown): Promise<void> { await ledger.record(kind, row); } };
