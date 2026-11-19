import { describe, it, expect, afterAll } from "vitest";
import { execSync } from "child_process";
import { appendFileSync, copyFileSync, cpSync, mkdirSync, mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cli = join(__dirname, "..", "..", "src", "cli.ts");
const project = mkdtempSync(join(tmpdir(), "sentinel-ignore-scan-"));
cpSync(join(__dirname, "..", "fixtures", "vulnerable-nextjs"), project, { recursive: true });
afterAll(() => rmSync(project, { recursive: true, force: true }));

function scan(format: "json" | "terminal", extra = "", dir = project): { out: string; status: number } {
  const cmd = `npx tsx ${cli} scan ${dir} --format ${format} ${extra}`;
  const opts = { encoding: "utf-8" as const, maxBuffer: 32 * 1024 * 1024, env: { ...process.env, SENTINEL_OFFLINE: "1" } };
  try {
    return { out: execSync(cmd, opts), status: 0 };
  } catch (e: any) {
    return { out: e.stdout ?? "", status: e.status ?? -1 };
  }
}

describe("integration: sentinel:ignore through the scan command", () => {
  it("an ignored finding leaves the totals and shows up counted and listed, in JSON and on the terminal", () => {
    const before = JSON.parse(scan("json").out);
    expect(before.summary.ignored_by_comment).toBe(0);
    expect(before.ignored_by_comment).toEqual([]);

    // A rule nothing special-cases: the first .ts finding of a rule other than the four that had their own check.
    const own = new Set(["AUTH-001", "AUTH-011", "CONVENTION-001", "PATTERN-001"]);
    const target = before.findings.find(
      (f: any) => f.ruleId && !own.has(f.ruleId) && /\.tsx?$/.test(f.evidence?.[0]?.file ?? ""),
    );
    expect(target).toBeDefined();
    const file: string = target.evidence[0].file;
    const moved = before.findings.filter((f: any) => f.ruleId === target.ruleId && f.evidence?.[0]?.file === file);
    appendFileSync(file, `\n// sentinel:ignore ${target.ruleId} reviewed\n`);

    const afterRun = scan("json");
    const after = JSON.parse(afterRun.out);
    expect(after.summary.ignored_by_comment).toBe(moved.length);
    expect(after.summary.total).toBe(before.summary.total - moved.length);
    expect(after.ignored_by_comment.map((i: any) => i.finding.id).sort()).toEqual(moved.map((f: any) => f.id).sort());
    expect(after.ignored_by_comment.every((i: any) => i.ruleId === target.ruleId && i.file === file && i.line > 0)).toBe(true);
    const ids = (r: any) => r.findings.map((f: any) => f.id).sort();
    const movedIds = new Set(moved.map((f: any) => f.id));
    expect(ids(after)).toEqual(ids(before).filter((id: string) => !movedIds.has(id)));
    // The rest of the project still fails the scan.
    expect(afterRun.status).toBe(1);

    const terminal = scan("terminal").out;
    expect(terminal).toContain(`Ignored: ${moved.length}`);
    expect(terminal).toContain(`IGNORED (${moved.length})`);
    expect(terminal).toContain(target.ruleId);
  }, 120_000);

  it("a finding under a test path is counted and listed as suppressed, and --no-dismiss shows it", () => {
    const dir = mkdtempSync(join(tmpdir(), "sentinel-suppressed-scan-"));
    try {
      cpSync(join(__dirname, "..", "fixtures", "vulnerable-nextjs"), dir, { recursive: true });
      const base = JSON.parse(scan("json", "", dir).out);

      // Copy a file that alarms into e2e/: the copy's findings are removed by the project context.
      const source = base.findings.find((f: any) => /src\/.*\.ts$/.test(f.evidence?.[0]?.file ?? "") && f.layer === "rules");
      mkdirSync(join(dir, "src", "e2e"), { recursive: true });
      copyFileSync(source.evidence[0].file, join(dir, "src", "e2e", "copied.ts"));

      const json = JSON.parse(scan("json", "", dir).out);
      const mine = json.suppressed.filter((s: any) => (s.finding.evidence?.[0]?.file ?? "").includes("/e2e/copied.ts"));
      expect(mine.length).toBeGreaterThanOrEqual(1);
      expect(mine.every((s: any) => s.reason.includes("e2e/"))).toBe(true);
      expect(json.summary.suppressed).toBe(json.suppressed.length);
      expect(json.findings.some((f: any) => (f.evidence?.[0]?.file ?? "").includes("/e2e/copied.ts"))).toBe(false);

      const quiet = scan("terminal", "", dir).out;
      expect(quiet).toContain(`Suppressed: ${json.suppressed.length}`);
      expect(quiet).not.toContain("e2e/copied.ts");
      const shown = scan("terminal", "--no-dismiss", dir).out;
      expect(shown).toContain(`SUPPRESSED BY PROJECT CONTEXT (${json.suppressed.length})`);
      expect(shown).toContain("e2e/copied.ts");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 120_000);
});
