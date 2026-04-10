import { describe, it, expect } from "vitest";
import { formatJson } from "../../src/output/json.js";
import type { Finding, ProjectModel } from "../../src/model/types.js";

const model: ProjectModel = {
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

const finding: Finding = {
  id: "TEST-1",
  domain: "secrets-exposure",
  severity: "critical",
  confidence: "high",
  title: "test",
  description: "",
  evidence: [],
  remediation: "",
  references: [],
  layer: "rules",
};

describe("json output", () => {
  it("produces valid JSON with summary", () => {
    const output = formatJson(model, [finding], { recon_ms: 100, rules_ms: 50 });
    const parsed = JSON.parse(output);
    expect(parsed.version).toBeDefined();
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.findings.length).toBe(1);
    expect(parsed.model.meta.stack).toBe("nextjs-supabase");
  });
});
