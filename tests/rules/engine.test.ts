import { describe, it, expect } from "vitest";
import { runRules, registerRule, resetRegistry } from "../../src/layers/rules/index.js";
import type { SecurityRule } from "../../src/layers/rules/registry.js";
import type { ProjectModel } from "../../src/model/types.js";

function emptyModel(): ProjectModel {
  return {
    meta: {
      name: "test",
      path: "/tmp",
      stack: "nextjs-supabase",
      packageManager: "npm",
      language: "typescript",
      framework: "nextjs-app",
      deployTarget: null,
    },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    findings: [],
  };
}

describe("rule engine", () => {
  it("runs registered rules and returns findings", async () => {
    resetRegistry();
    const rule: SecurityRule = {
      id: "TEST-001",
      domain: "secrets-exposure",
      title: "test rule",
      description: "always fires",
      severity: "low",
      appliesTo: ["nextjs-supabase"],
      references: {},
      check: () => [
        {
          id: "TEST-001-1",
          domain: "secrets-exposure",
          severity: "low",
          confidence: "high",
          title: "test finding",
          description: "fired",
          evidence: [],
          remediation: "none",
          references: [],
          layer: "rules",
          ruleId: "TEST-001",
        },
      ],
    };
    registerRule(rule);

    const findings = await runRules(emptyModel());
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe("TEST-001");
  });

  it("skips rules that do not apply to stack", async () => {
    resetRegistry();
    registerRule({
      id: "TEST-002",
      domain: "secrets-exposure",
      title: "wrong stack",
      description: "should be skipped",
      severity: "low",
      appliesTo: ["generic-web"],
      references: {},
      check: () => [{
        id: "TEST-002-1",
        domain: "secrets-exposure",
        severity: "low",
        confidence: "high",
        title: "fired",
        description: "",
        evidence: [],
        remediation: "",
        references: [],
        layer: "rules",
        ruleId: "TEST-002",
      }],
    });
    const findings = await runRules(emptyModel());
    expect(findings.length).toBe(0);
  });
});
