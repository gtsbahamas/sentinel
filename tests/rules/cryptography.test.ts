import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { cryptographyRules } from "../../src/layers/rules/domains/cryptography.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("cryptography rules", () => {
  it("flags Math.random in security context (CRYPTO-001)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags MD5 used for passwords (CRYPTO-002)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-002").length).toBeGreaterThanOrEqual(1);
  });

  it("flags ECB mode (CRYPTO-004)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-004").length).toBeGreaterThanOrEqual(1);
  });

  it("flags hardcoded HMAC key (CRYPTO-006)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-006").length).toBeGreaterThanOrEqual(1);
  });

  it("flags deprecated createCipher (CRYPTO-009)", async () => {
    resetRegistry();
    registerRules(cryptographyRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "CRYPTO-009").length).toBeGreaterThanOrEqual(1);
  });
});
