import { describe, it, expect } from "vitest";
import { spawnSync } from "child_process";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { getRules } from "../../src/layers/rules/registry.js";
import { registerAllRules } from "../../src/commands/register-rules.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..", "..");
const cli = join(root, "src", "cli.ts");

function run(args: string[]) {
  return spawnSync("npx", ["tsx", cli, ...args], { cwd: root, encoding: "utf-8" });
}

describe("scan --list-rules", () => {
  registerAllRules();
  const rules = [...getRules()];

  it("the registry has rules with unique ids", () => {
    expect(rules.length).toBeGreaterThan(0);
    expect(new Set(rules.map((r) => r.id)).size).toBe(rules.length);
  });

  it("prints one line per registered rule with id, severity and title, exit 0, no path needed", () => {
    const res = run(["scan", "--list-rules"]);
    expect(res.status).toBe(0);
    const lines = res.stdout.split("\n").filter((l) => l.trim() !== "");
    expect(lines).toHaveLength(rules.length);
    for (const rule of rules) {
      const line = lines.find((l) => l.split(/\s+/)[0] === rule.id);
      expect(line, `no line for ${rule.id}`).toBeDefined();
      expect(line).toContain(rule.severity);
      expect(line).toContain(rule.title);
    }
  });

  it("prints the same catalog as JSON with --format json", () => {
    const res = run(["scan", "--list-rules", "--format", "json"]);
    expect(res.status).toBe(0);
    const parsed = JSON.parse(res.stdout);
    expect(parsed).toEqual(
      rules.map((r) => ({ id: r.id, severity: r.severity, domain: r.domain, title: r.title })),
    );
  });

  it("still refuses a scan with no path", () => {
    const res = run(["scan"]);
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain("path");
  });
});
