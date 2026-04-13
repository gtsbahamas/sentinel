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

describe("sentinel scan --verify (integration)", () => {
  // The empty MockProvider throws on any call. When verify hits that path,
  // runVerify's safe-confirm fallback should fire: every rule finding is
  // kept as confirmed with a "verification failed" reason, and the scan
  // continues without crashing. This tests the end-to-end wiring:
  // flag → mergeVerifyConfig → runVerify → reporter → exit.
  it("runs with --verify --ai-provider mock and prints a VERIFICATION block", () => {
    const { stdout, exitCode } = sentinel([
      "scan",
      fixture,
      "--verify",
      "--ai-provider",
      "mock",
    ]);
    expect([0, 1]).toContain(exitCode);
    expect(stdout).toContain("VERIFICATION");
    expect(stdout).toMatch(/Verified: \d+ confirmed, \d+ dismissed, \d+ downgraded/);
  });

  it("without --verify, no VERIFICATION block appears", () => {
    const { stdout } = sentinel(["scan", fixture]);
    expect(stdout).not.toContain("VERIFICATION");
  });

  it("JSON output includes verification block when --verify is enabled", () => {
    const { stdout } = sentinel([
      "scan",
      fixture,
      "--verify",
      "--ai-provider",
      "mock",
      "--format",
      "json",
    ]);
    const parsed = JSON.parse(stdout);
    expect(parsed.verification).toBeDefined();
    expect(parsed.verification).toHaveProperty("confirmed");
    expect(parsed.verification).toHaveProperty("dismissed");
    expect(parsed.verification).toHaveProperty("downgraded");
    expect(parsed.verification).toHaveProperty("usage");
    expect(Array.isArray(parsed.verification.errors)).toBe(true);
  });

  it("JSON output omits verification block when --verify is not set", () => {
    const { stdout } = sentinel(["scan", fixture, "--format", "json"]);
    const parsed = JSON.parse(stdout);
    expect("verification" in parsed).toBe(false);
  });

  it("--no-dismiss keeps dismissed findings in the report (trust-building mode)", () => {
    // With the mock throwing, nothing actually gets dismissed — but the
    // flag should still route through without error and the reporter
    // should respect it (no DISMISSED section because dismissed[] is empty).
    const { stdout, exitCode } = sentinel([
      "scan",
      fixture,
      "--verify",
      "--no-dismiss",
      "--ai-provider",
      "mock",
    ]);
    expect([0, 1]).toContain(exitCode);
    expect(stdout).toContain("VERIFICATION");
  });

  it("--verify-min-severity passes findings below threshold straight through", () => {
    // Sub-threshold findings never hit the AI, so this runs end-to-end
    // cleanly even with the empty-dispatch mock.
    const { stdout, exitCode } = sentinel([
      "scan",
      fixture,
      "--verify",
      "--verify-min-severity",
      "critical",
      "--ai-provider",
      "mock",
    ]);
    expect([0, 1]).toContain(exitCode);
    expect(stdout).toContain("VERIFICATION");
  });
});
