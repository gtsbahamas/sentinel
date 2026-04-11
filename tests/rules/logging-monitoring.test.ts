import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { loggingMonitoringRules } from "../../src/layers/rules/domains/logging-monitoring.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("logging-monitoring rules", () => {
  it("flags sensitive value in log (LOG-001)", async () => {
    resetRegistry();
    registerRules(loggingMonitoringRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "LOG-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags console.log in API route (LOG-002)", async () => {
    resetRegistry();
    registerRules(loggingMonitoringRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "LOG-002").length).toBeGreaterThanOrEqual(1);
  });

  it("flags auth route without structured logger (LOG-009)", async () => {
    resetRegistry();
    registerRules(loggingMonitoringRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "LOG-009").length).toBeGreaterThanOrEqual(1);
  });
});
