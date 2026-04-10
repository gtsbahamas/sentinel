import { describe, it, expect } from "vitest";
import { formatTerminal } from "../../src/output/terminal.js";
import type { Finding, ProjectModel } from "../../src/model/types.js";

const sampleModel: ProjectModel = {
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

const sampleFinding: Finding = {
  id: "TEST-1",
  domain: "secrets-exposure",
  severity: "critical",
  confidence: "high",
  title: "test finding",
  description: "d",
  evidence: [{ file: "/tmp/a.ts", line: 1 }],
  remediation: "fix it",
  references: ["CWE-798"],
  layer: "rules",
};

describe("terminal output", () => {
  it("renders finding and summary", () => {
    const output = formatTerminal(sampleModel, [sampleFinding]);
    expect(output).toContain("SENTINEL");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("test finding");
    expect(output).toContain("secrets-exposure");
  });

  it("groups by severity", () => {
    const findings: Finding[] = [
      sampleFinding,
      { ...sampleFinding, id: "TEST-2", severity: "low", title: "low finding" },
    ];
    const output = formatTerminal(sampleModel, findings);
    const criticalIdx = output.indexOf("CRITICAL");
    const lowIdx = output.indexOf("LOW");
    expect(criticalIdx).toBeGreaterThanOrEqual(0);
    expect(lowIdx).toBeGreaterThan(criticalIdx);
  });
});
