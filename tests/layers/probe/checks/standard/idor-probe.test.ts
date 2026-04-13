import { describe, it, expect } from "vitest";
import { idorProbeCheck } from "../../../../../src/layers/probe/checks/standard/idor-probe.js";
import { MockHttpClient, TargetUnreachable } from "../../../../../src/layers/probe/http-client.js";
import { ProbeCleanupRegistry } from "../../../../../src/layers/probe/cleanup-registry.js";
import type { ProbeTarget, ProjectModel, Finding } from "../../../../../src/model/types.js";

function emptyModel(): ProjectModel {
  return {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [], endpoints: [], fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

const paramTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/users/:id",
  method: "GET",
  auth: "required",
  fromLayer: "rules",
  fromFindingId: "AUTH-IDOR-001",
  inputs: [{ name: "id", in: "path", type: "uuid" }],
};

const noParamTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/users",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "recon",
};

const baselineTarget: ProbeTarget = {
  kind: "baseline",
  url: "https://example.com",
  fromLayer: "recon",
};

const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff";

describe("idor-probe check", () => {
  it("appliesTo — true for endpoint with UUID path input, false for no-param endpoint and baseline", () => {
    expect(idorProbeCheck.appliesTo(paramTarget, emptyModel())).toBe(true);
    expect(idorProbeCheck.appliesTo(noParamTarget, emptyModel())).toBe(false);
    expect(idorProbeCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("confirms IDOR when 200 with non-empty body is returned for a sentinel UUID", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /\/api\/users\/0{8}/ },
        response: {
          status: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ id: NIL_UUID, name: "Ghost User", email: "ghost@example.com" }),
        },
      },
    ], 10);

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const idorFinding = result.findings.find((f) => f.cwe === "CWE-639" && f.severity === "high");
    expect(idorFinding).toBeDefined();
    expect(idorFinding!.domain).toBe("auth-access-control");
    expect(idorFinding!.layer).toBe("probe");
    expect(idorFinding!.severity).toBe("high");
    expect(idorFinding!.confidence).toBe("confirmed");
  });

  it("produces no findings when 401/403 returned and no prior finding", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /\/api\/users\// },
        response: {
          status: 401,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: "Unauthorized" }),
        },
      },
    ], 10);

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
    expect(result.confirmed).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
  });

  it("refutes prior IDOR finding when all sentinel UUIDs return 401/403", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /\/api\/users\// },
        response: {
          status: 403,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: "Forbidden" }),
        },
      },
    ], 10);

    const priorFinding: Finding = {
      id: "RULE-IDOR-001",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Potential IDOR on user endpoint",
      description: "Static analysis detected insufficient ownership validation on user resource endpoint",
      evidence: [{ file: "src/app/api/users/[id]/route.ts" }],
      remediation: "",
      references: [],
      layer: "rules",
      ruleId: "IDOR-001",
    };

    const targetWithPrior: ProbeTarget = {
      ...paramTarget,
      fromFindingId: "RULE-IDOR-001",
    };

    const result = await idorProbeCheck.run({
      target: targetWithPrior,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.refuted).toHaveLength(1);
    expect(result.refuted[0].findingId).toBe("RULE-IDOR-001");
    const refuteFinding = result.findings.find((f) => f.refutes === "RULE-IDOR-001");
    expect(refuteFinding).toBeDefined();
    expect(refuteFinding!.severity).toBe("info");
  });

  it("404 is no signal — neither confirms nor refutes prior finding", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /\/api\/users\// },
        response: {
          status: 404,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: "Not found" }),
        },
      },
    ], 10);

    const priorFinding: Finding = {
      id: "RULE-IDOR-002",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Potential IDOR on user endpoint",
      description: "Static analysis detected insufficient ownership validation",
      evidence: [{ file: "src/app/api/users/[id]/route.ts" }],
      remediation: "",
      references: [],
      layer: "rules",
      ruleId: "IDOR-002",
    };

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
    expect(result.confirmed).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
  });

  it("handles target unreachable gracefully — returns error, no findings", async () => {
    const client = new MockHttpClient([], 10);
    client.request = async (_req) => {
      throw new TargetUnreachable("https://api.example.com/api/users/00000000-0000-0000-0000-000000000000");
    };

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.confirmed).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].kind).toBe("target-unreachable");
    expect(result.errors[0].checkId).toBe("idor-probe");
  });
});
