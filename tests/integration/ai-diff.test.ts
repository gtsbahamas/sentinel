import { describe, it, expect, beforeAll } from "vitest";
import { execFileSync } from "child_process";
import { writeFileSync, mkdtempSync } from "fs";
import { join, dirname } from "path";
import { tmpdir } from "os";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");

describe("sentinel diff with AI findings (integration)", () => {
  let baselinePath: string;
  let currentPath: string;

  beforeAll(() => {
    const tmp = mkdtempSync(join(tmpdir(), "sentinel-diff-"));
    baselinePath = join(tmp, "baseline.json");
    currentPath = join(tmp, "current.json");

    const baseline = {
      meta: { name: "demo", path: "/demo", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
      runInfo: { recon_ms: 0, rules_ms: 0, ai_ms: 0, ai: { enabled: false } },
      findings: [
        { id: "r:AUTH-001:a.ts:1", ruleId: "AUTH-001", domain: "auth-access-control", severity: "high", confidence: "high", title: "rule", description: "x", evidence: [{ file: "a.ts", line: 1 }], remediation: "x", references: [], layer: "rules" },
      ],
    };

    const current = {
      ...baseline,
      findings: [
        ...baseline.findings,
        { id: "ai:AI-IDOR-001:b.ts:5", ruleId: "AI-IDOR-001", domain: "auth-access-control", severity: "high", confidence: "medium", title: "ai finding", description: "y", evidence: [{ file: "b.ts", line: 5 }], remediation: "y", references: [], layer: "ai" },
      ],
    };

    writeFileSync(baselinePath, JSON.stringify(baseline));
    writeFileSync(currentPath, JSON.stringify(current));
  });

  it("shows the new AI finding in the diff output with layer breakdown", () => {
    // diff may return exit code 0 OR 1 depending on --fail-on default — wrap in try/catch
    let stdout: string;
    try {
      stdout = execFileSync(
        "npx",
        ["tsx", join(repoRoot, "src", "cli.ts"), "diff", baselinePath, currentPath],
        { cwd: repoRoot, encoding: "utf-8", maxBuffer: 16 * 1024 * 1024 },
      );
    } catch (err) {
      const e = err as { stdout?: string; status?: number };
      stdout = e.stdout ?? "";
    }
    // Should show either the AI finding's ruleId or the per-layer breakdown
    expect(stdout).toMatch(/AI-IDOR-001|ai.*: 1/);
  });
});
