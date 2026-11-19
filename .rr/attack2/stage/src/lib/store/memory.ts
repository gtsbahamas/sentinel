type Session = { id: string; logTokenHash: string };
type Log = { id: string; tokenHash: string };

// An in-memory table: these comparisons find a row by its key, like an index lookup.
export class MemoryStore {
  private sessions = new Map<string, Session>();
  private logs: Log[] = [];

  findSessionByTokenHash(tokenHash: string): Session | null {
    for (const s of this.sessions.values()) if (s.logTokenHash === tokenHash) return s;
    return null;
  }

  logByTokenHash(tokenHash: string): Log | undefined {
    return this.logs.find((l) => l.tokenHash === tokenHash);
  }

  deleteLog(tokenHash: string): boolean {
    for (const [i, l] of this.logs.entries()) {
      if (l.tokenHash === tokenHash) {
        this.logs.splice(i, 1);
        return true;
      }
    }
    return false;
  }
}
