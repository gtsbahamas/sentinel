import { describe, it, expect } from "vitest";
import { execSync } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");
const cli = join(__dirname, "..", "..", "src", "cli.ts");

describe("integration: scan command", () => {
  it("runs full scan and produces terminal output", () => {
    let output = "";
    try {
      output = execSync(`npx tsx ${cli} scan ${fixturePath} --format terminal`, {
        encoding: "utf-8",
      });
    } catch (e: any) {
      // Exit code 1 means findings were found; stdout still has the report
      output = e.stdout ?? "";
    }
    expect(output).toContain("SENTINEL");
    expect(output).toContain("CRITICAL");
    expect(output).toMatch(/secrets-exposure|SECRETS/i);
  });

  it("produces JSON output with findings", () => {
    let output = "";
    try {
      output = execSync(`npx tsx ${cli} scan ${fixturePath} --format json`, {
        encoding: "utf-8",
      });
    } catch (e: any) {
      output = e.stdout ?? "";
    }
    const parsed = JSON.parse(output);
    expect(parsed.findings.length).toBeGreaterThan(5);
    expect(parsed.summary.critical).toBeGreaterThanOrEqual(1);
    expect(parsed.project.stack).toBe("nextjs-supabase");
  });

  it("exits non-zero when --fail-on high is triggered", () => {
    try {
      execSync(`npx tsx ${cli} scan ${fixturePath} --fail-on high`, { encoding: "utf-8" });
      throw new Error("Expected non-zero exit");
    } catch (e: any) {
      expect(e.status).toBe(1);
    }
  });
});
