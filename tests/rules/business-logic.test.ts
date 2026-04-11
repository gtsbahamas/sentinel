import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { businessLogicRules } from "../../src/layers/rules/domains/business-logic.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("business-logic rules", () => {
  it("flags distinct login errors (BIZ-001)", async () => {
    resetRegistry();
    registerRules(businessLogicRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "BIZ-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags signup accepting role from body (BIZ-008)", async () => {
    resetRegistry();
    registerRules(businessLogicRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "BIZ-008").length).toBeGreaterThanOrEqual(1);
  });

  it("flags signup without captcha (BIZ-010)", async () => {
    resetRegistry();
    registerRules(businessLogicRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "BIZ-010").length).toBeGreaterThanOrEqual(1);
  });
});
