import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { ProbeLogger } from "../../../src/layers/probe/probe-log.js";
import type { ProbeLogEntry } from "../../../src/layers/probe/http-client.js";

function makeEntry(requestId: string): ProbeLogEntry {
  return {
    requestId,
    timestamp: new Date().toISOString(),
    request: { method: "GET", url: "http://example.com", headers: {} },
    response: { status: 200, headers: {}, bodyPreview: "ok", timingMs: 42 },
  };
}

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "probe-log-test-"));
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
});

describe("ProbeLogger", () => {
  it("init creates directory if missing", async () => {
    const logDir = join(tmpDir, "nested", "deep");
    const logger = new ProbeLogger(logDir, "run-001");

    expect(existsSync(logDir)).toBe(false);
    await logger.init();
    expect(existsSync(logDir)).toBe(true);
  });

  it("append writes JSONL entries", async () => {
    const logger = new ProbeLogger(tmpDir, "run-002");
    await logger.init();

    await logger.append(makeEntry("req-1"));
    await logger.append(makeEntry("req-2"));

    const content = await readFile(logger.getLogPath(), "utf-8");
    const lines = content.trim().split("\n");

    expect(lines).toHaveLength(2);

    const first = JSON.parse(lines[0]) as ProbeLogEntry;
    const second = JSON.parse(lines[1]) as ProbeLogEntry;

    expect(first.requestId).toBe("req-1");
    expect(second.requestId).toBe("req-2");
    expect(first.response?.status).toBe(200);
  });

  it("rotate keeps only the last N log files", async () => {
    // Pre-create 5 probe-log files with alphabetically sortable names
    for (let i = 1; i <= 5; i++) {
      await writeFile(join(tmpDir, `probe-log-run-00${i}.jsonl`), "");
    }

    const logger = new ProbeLogger(tmpDir, "run-006");
    const removed = await logger.rotate(3);

    expect(removed).toBe(2);

    // Oldest two (run-001, run-002) should be gone; newest three remain
    expect(existsSync(join(tmpDir, "probe-log-run-001.jsonl"))).toBe(false);
    expect(existsSync(join(tmpDir, "probe-log-run-002.jsonl"))).toBe(false);
    expect(existsSync(join(tmpDir, "probe-log-run-003.jsonl"))).toBe(true);
    expect(existsSync(join(tmpDir, "probe-log-run-004.jsonl"))).toBe(true);
    expect(existsSync(join(tmpDir, "probe-log-run-005.jsonl"))).toBe(true);
  });

  it("rotate is no-op when under limit", async () => {
    await writeFile(join(tmpDir, "probe-log-run-001.jsonl"), "");
    await writeFile(join(tmpDir, "probe-log-run-002.jsonl"), "");

    const logger = new ProbeLogger(tmpDir, "run-003");
    const removed = await logger.rotate(10);

    expect(removed).toBe(0);
    expect(existsSync(join(tmpDir, "probe-log-run-001.jsonl"))).toBe(true);
    expect(existsSync(join(tmpDir, "probe-log-run-002.jsonl"))).toBe(true);
  });

  it("getLogPath returns correct path", () => {
    const logger = new ProbeLogger("/some/log/dir", "abc-123");
    expect(logger.getLogPath()).toBe("/some/log/dir/probe-log-abc-123.jsonl");
  });
});
