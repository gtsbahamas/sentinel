import { describe, it, expect } from "vitest";
import { runRecon } from "../../src/layers/recon/index.js";
import { runRules, registerRules, resetRegistry } from "../../src/layers/rules/index.js";
import { authAccessControlRules } from "../../src/layers/rules/domains/auth-access-control.js";
import { loggingMonitoringRules } from "../../src/layers/rules/domains/logging-monitoring.js";
import { inferContext } from "../../src/layers/context/index.js";
import { applyContextSuppressions } from "../../src/layers/context/suppression.js";
import { resolve } from "path";

const FIXTURE = resolve("tests/fixtures/context/single-org-nextjs");

describe("context-aware scan pipeline", () => {
  it("reduces findings when context is applied", async () => {
    const model = await runRecon(FIXTURE, []);

    resetRegistry();
    registerRules(authAccessControlRules);
    registerRules(loggingMonitoringRules);

    const context = await inferContext(model);
    const rawFindings = await runRules(model, context);
    const suppressed = applyContextSuppressions(rawFindings, context);

    // LOG-005 findings should be downgraded to info
    const logFindings = suppressed.filter((f) => f.ruleId === "LOG-005");
    for (const f of logFindings) {
      expect(f.severity).toBe("info");
    }
  });
});
