const rows: unknown[] = [];

export const ledger = {
  async record(kind: string, row: unknown): Promise<void> {
    rows.push({ kind, row });
  },
  async remove(key: string): Promise<boolean> {
    return rows.length > 0 && key.length > 0;
  },
  async bump(key: string): Promise<number> {
    rows.push(key);
    return rows.length;
  },
};
