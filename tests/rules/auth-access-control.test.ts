import { describe, it, expect } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

describe("auth-access-control rules", () => {
  it("flags mutation endpoint without auth (AUTH-001)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth001 = findings.filter((f) => f.ruleId === "AUTH-001");
    expect(auth001.length).toBeGreaterThanOrEqual(1);
  });

  it("flags params.id without ownership check (AUTH-004)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth004 = findings.filter((f) => f.ruleId === "AUTH-004");
    expect(auth004.length).toBeGreaterThanOrEqual(1);
  });

  it("flags auth.admin usage without server-only import (AUTH-005)", async () => {
    resetRegistry();
    registerRules(authAccessControlRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const auth005 = findings.filter((f) => f.ruleId === "AUTH-005");
    expect(auth005.length).toBeGreaterThanOrEqual(1);
  });
});
