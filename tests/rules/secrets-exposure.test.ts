import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { secretsExposureRules } from "../../src/layers/rules/domains/secrets-exposure.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("secrets-exposure rules", () => {
  it("flags service role key used client-side (SECRETS-001)", async () => {
    resetRegistry();
    registerRules(secretsExposureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const secrets001 = findings.filter((f) => f.ruleId === "SECRETS-001");
    expect(secrets001.length).toBeGreaterThanOrEqual(1);
    expect(secrets001[0].severity).toBe("critical");
  });

  it("flags hardcoded credentials (SECRETS-004)", async () => {
    resetRegistry();
    registerRules(secretsExposureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const secrets004 = findings.filter((f) => f.ruleId === "SECRETS-004");
    expect(secrets004.length).toBeGreaterThanOrEqual(1);
  });

  it("flags env vars missing from .env.example (SECRETS-008)", async () => {
    resetRegistry();
    registerRules(secretsExposureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const secrets008 = findings.filter((f) => f.ruleId === "SECRETS-008");
    expect(secrets008.length).toBeGreaterThanOrEqual(1);
  });
});
