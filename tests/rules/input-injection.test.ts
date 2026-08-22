import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { inputInjectionRules } from "../../src/layers/rules/domains/input-injection.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { dirname } from "path";
import { fileURLToPath } from "url";
import { stagedFixture } from "./helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = stagedFixture("vulnerable-nextjs");

describe("input-injection rules", () => {
  it("flags dangerouslySetInnerHTML without sanitizer (INPUT-001)", async () => {
    resetRegistry();
    registerRules(inputInjectionRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const input001 = findings.filter((f) => f.ruleId === "INPUT-001");
    expect(input001.length).toBeGreaterThanOrEqual(1);
    expect(input001[0].severity).toBe("critical");
  });

  it("flags API route missing validation (INPUT-005)", async () => {
    resetRegistry();
    registerRules(inputInjectionRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const input005 = findings.filter((f) => f.ruleId === "INPUT-005");
    expect(input005.length).toBeGreaterThanOrEqual(1);
  });
});
