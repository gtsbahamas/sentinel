import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import type { Finding, AIRunResult } from "../../src/model/types.js";
import type { ScanEvent } from "../../src/dashboard/events.js";

// Stand-ins for the two layers that would reach a model or a live target.
const aiFindings: Finding[] = [];
vi.mock("../../src/layers/ai/index.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/layers/ai/index.js")>()),
  runAI: vi.fn(async (): Promise<AIRunResult> => ({
    findings: aiFindings,
    usage: { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, estimatedCostUsd: 0 },
    stageA: null,
    errors: [],
    budgetExhausted: false,
    endpointsAnalyzed: 0,
    endpointsSkipped: 0,
    findingsCollapsed: 0,
    magicLinkCapped: 0,
    durationMs: 0,
  })),
}));
vi.mock("../../src/layers/probe/index.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../src/layers/probe/index.js")>()),
  runProbe: vi.fn(async (_model: unknown, ruleFindings: Finding[]) => ({
    mergedFindings: ruleFindings,
    result: {
      findings: [],
      confirmedFindingIds: [],
      refutedFindingIds: [],
      usedRequests: 0,
      requestCap: 0,
      aggressionLevel: "passive",
      targetOrigin: "http://localhost:3999",
      errors: [],
      cleanupObligationsExecuted: 0,
      cleanupObligationsFailed: 0,
      cleanupFailures: [],
      probeLogPath: "",
      durationMs: 0,
    },
  })),
}));

const { runScan } = await import("../../src/commands/scan.js");
const { runProbeCommand } = await import("../../src/commands/probe.js");
const { runFixCommand } = await import("../../src/commands/fix.js");
const { ScanEventEmitter } = await import("../../src/dashboard/events.js");

// MD5 trips CRYPTO-002 (critical): one copy under the ignored `tools/`, one in `src/`.
const MD5 = 'import { createHash } from "crypto";\nexport const h = (s: string) => createHash("md5").update(s).digest("hex");\n';

function aiFinding(id: string, file: string): Finding {
  return {
    id,
    ruleId: "AI-TEST",
    domain: "api-security",
    severity: "high",
    confidence: "high",
    title: `ai ${id}`,
    description: "",
    evidence: [{ file, line: 1 }],
    remediation: "",
    references: [],
    layer: "ai",
  };
}

let project: string;
let stdout: string[];
let stderr: string[];

beforeEach(() => {
  project = mkdtempSync(join(tmpdir(), "sentinel-ignored-"));
  writeFileSync(join(project, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
  writeFileSync(
    join(project, "package-lock.json"),
    JSON.stringify({ name: "x", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "x", version: "1.0.0" } } }),
  );
  mkdirSync(join(project, "tools"));
  mkdirSync(join(project, "src"));
  writeFileSync(join(project, "tools", "hash.ts"), MD5);
  writeFileSync(join(project, "src", "hash.ts"), MD5);
  writeFileSync(join(project, ".sentinelrc.json"), JSON.stringify({ ignore: ["tools/"] }));
  aiFindings.length = 0;
  stdout = [];
  stderr = [];
  vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
    stdout.push(String(chunk));
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
    stderr.push(String(chunk));
    return true;
  });
  for (const key of ["SHIPSAFE_URL", "SHIPSAFE_TOKEN", "SHIPSAFE_PROJECT_ID", "SHIPSAFE_RUN_ID"]) vi.stubEnv(key, "");
  vi.stubEnv("SENTINEL_OFFLINE", "1");
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  rmSync(project, { recursive: true, force: true });
});

const inTools = (file: string) => file.includes("/tools/") || file.startsWith("tools/");

function collect() {
  const emitter = new ScanEventEmitter();
  const events: ScanEvent[] = [];
  emitter.on("scan-event", (e: ScanEvent) => events.push(e));
  return { emitter, events };
}

function complete(events: ScanEvent[]) {
  const done = events.filter((e) => e.type === "scan:complete");
  expect(done).toHaveLength(1);
  const event = done[0];
  if (event.type !== "scan:complete") throw new Error("unreachable");
  return event.summary;
}

describe("scan: ignored findings on the dashboard", () => {
  it("lists them on scan:complete, outside the severity counts and the finding events", async () => {
    const { emitter, events } = collect();
    await runScan({ path: project, format: "json", outFile: join(project, "out.json"), emitter });

    const report = JSON.parse(readFileSync(join(project, "out.json"), "utf-8"));
    const ignoredIds = report.ignored.map((f: Finding) => f.id);
    expect(ignoredIds.length).toBeGreaterThan(0);

    const summary = complete(events);
    expect(summary.ignored.map((f) => f.id)).toEqual(ignoredIds);
    expect(summary.ignored.every((f) => inTools(f.file))).toBe(true);
    // Counts are the kept findings only, as in every other report.
    expect(summary.findings.critical).toBe(report.summary.critical);
    const findingEvents = events.flatMap((e) => (e.type === "finding" ? [e.data] : []));
    expect(findingEvents.map((f) => f.id)).toEqual(report.findings.map((f: Finding) => f.id));
    expect(findingEvents.some((f) => inTools(f.file))).toBe(false);
  });

  it("says none when nothing is ignored", async () => {
    writeFileSync(join(project, ".sentinelrc.json"), JSON.stringify({}));
    const { emitter, events } = collect();
    await runScan({ path: project, format: "json", outFile: join(project, "out.json"), emitter });
    expect(complete(events).ignored).toEqual([]);
  });
});

describe("scan: AI-layer findings under an ignored path", () => {
  it("are listed as ignored, not as findings", async () => {
    aiFindings.push(aiFinding("AI-IGNORED", join(project, "tools", "hash.ts")), aiFinding("AI-KEPT", join(project, "src", "hash.ts")));
    await runScan({ path: project, format: "json", outFile: join(project, "out.json"), ai: true, aiProvider: "mock" });
    const report = JSON.parse(readFileSync(join(project, "out.json"), "utf-8"));
    expect(report.ignored.map((f: Finding) => f.id)).toContain("AI-IGNORED");
    expect(report.findings.map((f: Finding) => f.id)).toContain("AI-KEPT");
    expect(report.findings.map((f: Finding) => f.id)).not.toContain("AI-IGNORED");
  });
});

describe("scan: ShipSafe push", () => {
  it("sends only the kept findings, and says how many ignored ones it left out", async () => {
    const pushed: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: { body: string }) => {
        if (url.endsWith("/api/scans")) return new Response(JSON.stringify({ scan_id: "s1" }), { status: 201 });
        if (url.endsWith("/findings")) {
          const body = JSON.parse(init.body) as { findings: { sentinel_finding_id: string; evidence?: { file: string } }[] };
          for (const f of body.findings) pushed.push(f.evidence?.file ?? "");
          return new Response(JSON.stringify({ inserted: body.findings.length }), { status: 201 });
        }
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }),
    );
    await runScan({
      path: project,
      format: "json",
      outFile: join(project, "out.json"),
      shipsafeUrl: "https://shipsafe.invalid",
      shipsafeToken: "test-token",
      shipsafeProjectId: "p1",
    });
    const report = JSON.parse(readFileSync(join(project, "out.json"), "utf-8"));
    expect(pushed.length).toBe(report.findings.length);
    expect(pushed.some(inTools)).toBe(false);
    expect(stderr.join("")).toContain(`[shipsafe] ${report.ignored.length} ignored finding(s) not pushed`);
  });
});

describe("probe: ignored findings", () => {
  const probe = (format: "json" | "terminal") =>
    runProbeCommand({ path: project, target: "http://localhost:3999", level: "passive", authorize: true, format });

  it("are listed in the JSON report and do not set the exit code", async () => {
    writeFileSync(join(project, "src", "hash.ts"), "export const ok = 1;\n");
    const code = await probe("json");
    const report = JSON.parse(stdout.join(""));
    expect(report.ignored.length).toBeGreaterThan(0);
    expect(report.ignored.every((f: Finding) => f.evidence.every((e) => inTools(e.file)))).toBe(true);
    expect(report.summary.ignored).toBe(report.ignored.length);
    expect(report.findings.some((f: Finding) => f.evidence.some((e) => inTools(e.file)))).toBe(false);
    expect(code).toBe(0);
  });

  it("are listed in the terminal report", async () => {
    await probe("terminal");
    expect(stdout.join("")).toContain("IGNORED BY .sentinelrc.json");
  });
});

describe("fix: ignored findings", () => {
  it("are named on stderr and not offered for fixing", async () => {
    await runFixCommand({ path: project, dryRun: true, noAI: true });
    const err = stderr.join("");
    expect(err).toMatch(/Ignored by \.sentinelrc\.json \(\d+\), not offered for fixing:/);
    expect(err).toContain(join("tools", "hash.ts"));
    expect(stdout.join("")).not.toContain(join("tools", "hash.ts"));
    expect(stdout.join("")).toContain(join("src", "hash.ts"));
  });

  it("are listed on the dashboard's scan:complete of a fix round", async () => {
    const { emitter, events } = collect();
    await runFixCommand({ path: project, converge: true, maxRounds: 1, noAI: true, emitter });
    const summary = complete(events);
    expect(summary.ignored.length).toBeGreaterThan(0);
    expect(summary.ignored.every((f) => inTools(f.file))).toBe(true);
    expect(summary.findings.critical).toBeGreaterThan(0);
  });
});
