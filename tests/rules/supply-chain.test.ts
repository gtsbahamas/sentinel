import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { supplyChainRules } from "../../src/layers/rules/domains/supply-chain.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("supply-chain rules", () => {
  it("flags flatmap-stream (SUPPLY-001)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "SUPPLY-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags missing lockfile (SUPPLY-002)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "SUPPLY-002").length).toBe(1);
  });

  it("flags postinstall lifecycle script (SUPPLY-003)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "SUPPLY-003").length).toBeGreaterThanOrEqual(1);
  });

  it("flags wildcard version (SUPPLY-004)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "SUPPLY-004").length).toBeGreaterThanOrEqual(1);
  });

  it("flags deprecated package (SUPPLY-010)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const deprecated = findings.filter((f) => f.ruleId === "SUPPLY-010");
    expect(deprecated.length).toBeGreaterThanOrEqual(1);
    expect(deprecated.some((f) => /request/.test(f.title))).toBe(true);
  });
});
