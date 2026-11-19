import { appendFile, readdir, unlink, mkdir } from "fs/promises";
import { existsSync } from "fs";
import { join } from "path";
import type { ProbeLogEntry } from "./http-client.js";

export class ProbeLogger {
  private readonly logPath: string;

  constructor(logDir: string, runId: string) {
    this.logPath = join(logDir, `probe-log-${runId}.jsonl`);
  }

  getLogPath(): string {
    return this.logPath;
  }

  async init(): Promise<void> {
    const dir = this.logPath.replace(/\/[^/]+$/, "");
    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true });
    }
  }

  async append(entry: ProbeLogEntry): Promise<void> {
    await appendFile(this.logPath, JSON.stringify(entry) + "\n", "utf-8");
  }

  async rotate(keepLast = 10): Promise<number> {
    const dir = this.logPath.replace(/\/[^/]+$/, "");
    if (!existsSync(dir)) return 0;

    const files = await readdir(dir);
    const probeFiles = files
      .filter((f) => f.startsWith("probe-log-") && f.endsWith(".jsonl"))
      .sort();

    let removed = 0;
    while (probeFiles.length > keepLast) {
      const oldest = probeFiles.shift()!;
      await unlink(join(dir, oldest));
      removed++;
    }
    return removed;
  }
}
