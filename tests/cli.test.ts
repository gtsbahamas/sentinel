import { describe, it, expect } from "vitest";
import { execSync } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const cli = join(__dirname, "..", "src", "cli.ts");

describe("cli", () => {
  it("shows help when --help passed", () => {
    const output = execSync(`npx tsx ${cli} --help`, { encoding: "utf-8" });
    expect(output).toContain("sentinel");
    expect(output).toContain("scan");
  });

  it("shows version when --version passed", () => {
    const output = execSync(`npx tsx ${cli} --version`, { encoding: "utf-8" });
    expect(output).toMatch(/\d+\.\d+\.\d+/);
  });
});
