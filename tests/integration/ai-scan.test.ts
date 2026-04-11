import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const fixture = join(repoRoot, "tests", "fixtures", "ai-scan");

function sentinel(args: string[]): { stdout: string; exitCode: number } {
  try {
    const stdout = execFileSync("npx", ["tsx", join(repoRoot, "src", "cli.ts"), ...args], {
      cwd: repoRoot,
      encoding: "utf-8",
      maxBuffer: 16 * 1024 * 1024,
    });
    return { stdout, exitCode: 0 };
  } catch (err) {
    const e = err as { stdout?: string; status?: number };
    return { stdout: e.stdout ?? "", exitCode: e.status ?? 1 };
  }
}

describe("sentinel scan --ai (integration)", () => {
  it("runs with --ai --ai-provider mock without crashing", () => {
    const { stdout, exitCode } = sentinel(["scan", fixture, "--ai", "--ai-provider", "mock"]);
    // Exit 1 is fine — rule-layer findings are expected from the fixture.
    expect([0, 1]).toContain(exitCode);
    expect(stdout).toContain("AI Analysis");
  });

  it("--ai-dry-run prints estimate and exits 0 without a real provider", () => {
    const { stdout, exitCode } = sentinel(["scan", fixture, "--ai", "--ai-dry-run", "--ai-provider", "mock"]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("AI Dry Run");
    expect(stdout).toContain("Endpoints to analyze:");
  });

  it("JSON output includes runInfo.ai with mock provider", () => {
    const { stdout } = sentinel(["scan", fixture, "--ai", "--ai-provider", "mock", "--format", "json"]);
    const parsed = JSON.parse(stdout);
    expect(parsed.runInfo.ai).toBeDefined();
    expect(parsed.runInfo.ai.enabled).toBe(true);
  });

  it("runs without --ai and produces no AI section", () => {
    const { stdout } = sentinel(["scan", fixture]);
    expect(stdout).not.toContain("AI Analysis");
  });
});
