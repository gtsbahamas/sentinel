import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { apiSecurityRules } from "../../src/layers/rules/domains/api-security.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("api-security rules", () => {
  it("flags auth endpoint without rate limit (API-002)", async () => {
    resetRegistry();
    registerRules(apiSecurityRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "API-002").length).toBeGreaterThanOrEqual(1);
  });

  it("flags mass assignment via body spread (API-003)", async () => {
    resetRegistry();
    registerRules(apiSecurityRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "API-003").length).toBeGreaterThanOrEqual(1);
  });

  it("flags unbounded GET list (API-004)", async () => {
    resetRegistry();
    registerRules(apiSecurityRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "API-004").length).toBeGreaterThanOrEqual(1);
  });
});
