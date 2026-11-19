import { randomUUID } from "crypto";

export interface CleanupObligation {
  description: string;
  severity: "blocking" | "best-effort";
  timeoutMs?: number;
  cleanup: (signal: AbortSignal) => Promise<void>;
}

export interface CleanupResult {
  executed: number;
  failed: number;
  failures: Array<{
    obligationId: string;
    description: string;
    error: string;
    severity: "blocking" | "best-effort";
  }>;
}

interface RegisteredObligation extends CleanupObligation {
  id: string;
}

export interface CleanupRegistry {
  register(obligation: CleanupObligation): string;
  executeAll(): Promise<CleanupResult>;
  pendingCount(): number;
}

export class ProbeCleanupRegistry implements CleanupRegistry {
  private obligations: RegisteredObligation[] = [];
  private executed = false;

  register(obligation: CleanupObligation): string {
    if (this.executed) {
      throw new Error("Cannot register obligations after cleanup has run");
    }
    const id = `cleanup-${randomUUID().slice(0, 8)}`;
    this.obligations.push({ ...obligation, id });
    return id;
  }

  pendingCount(): number {
    return this.obligations.length;
  }

  async executeAll(): Promise<CleanupResult> {
    if (this.executed) {
      return { executed: 0, failed: 0, failures: [] };
    }
    this.executed = true;

    const result: CleanupResult = { executed: 0, failed: 0, failures: [] };
    const reversed = [...this.obligations].reverse();

    for (const ob of reversed) {
      const timeoutMs = ob.timeoutMs ?? 30_000;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        await ob.cleanup(controller.signal);
        result.executed++;
      } catch (err) {
        result.failed++;
        result.failures.push({
          obligationId: ob.id,
          description: ob.description,
          error: err instanceof Error ? err.message : String(err),
          severity: ob.severity,
        });
      } finally {
        clearTimeout(timer);
      }
    }

    this.obligations = [];
    return result;
  }
}
