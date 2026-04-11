import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { infrastructureRules } from "../../src/layers/rules/domains/infrastructure.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("infrastructure rules", () => {
  it("flags missing Content-Security-Policy (INFRA-001)", async () => {
    resetRegistry();
    registerRules(infrastructureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "INFRA-001").length).toBe(1);
  });

  it("flags missing X-Frame-Options (INFRA-003)", async () => {
    resetRegistry();
    registerRules(infrastructureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "INFRA-003").length).toBe(1);
  });

  it("flags Supabase email confirmations disabled (INFRA-010)", async () => {
    resetRegistry();
    registerRules(infrastructureRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "INFRA-010").length).toBe(1);
  });
});
