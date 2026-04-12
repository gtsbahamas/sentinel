import { describe, it, expect } from "vitest";
import { endpointEnumerationCheck } from "../../../../../src/layers/probe/checks/passive/endpoint-enumeration.js";
import { MockHttpClient } from "../../../../../src/layers/probe/http-client.js";
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

const baseEndpointTarget: ProbeTarget = {
  kind: "endpoint",
  url: "http://localhost:3000/api/user",
  method: "GET",
  auth: "required",
  fromLayer: "recon",
};

describe("endpoint-enumeration check", () => {
  it("applies only to endpoint targets (endpoint=true, baseline=false)", () => {
    const endpoint: ProbeTarget = { ...baseEndpointTarget, kind: "endpoint" };
    const baseline: ProbeTarget = { ...baseEndpointTarget, kind: "baseline" };

    expect(endpointEnumerationCheck.appliesTo(endpoint, emptyModel())).toBe(true);
    expect(endpointEnumerationCheck.appliesTo(baseline, emptyModel())).toBe(false);
  });

  it("detects auth bypass when protected endpoint returns 200", async () => {
    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000/api/user" },
        response: { status: 200, headers: {}, body: '{"id":"123"}' },
      },
    ]);

    const result = await endpointEnumerationCheck.run({
      target: { ...baseEndpointTarget, auth: "required" },
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);

    const finding = result.findings[0];
    expect(finding.severity).toBe("high");
    expect(finding.cwe).toBe("CWE-306");
    expect(finding.domain).toBe("auth-access-control");
    expect(finding.probeEvidence.response.status).toBe(200);
  });

  it("produces no finding when protected endpoint returns 401", async () => {
    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000/api/user" },
        response: { status: 401, headers: {}, body: "Unauthorized" },
      },
    ]);

    const result = await endpointEnumerationCheck.run({
      target: { ...baseEndpointTarget, auth: "required" },
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

  it("refutes prior finding when unauthenticated endpoint returns 403", async () => {
    const priorFinding: Finding = {
      id: "RULE-AUTH-001",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Endpoint may lack auth",
      description: "Static analysis suspects missing auth",
      evidence: [],
      remediation: "Add auth middleware",
      references: [],
      layer: "rules",
    };

    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000/api/user" },
        response: { status: 403, headers: {}, body: "Forbidden" },
      },
    ]);

    const result = await endpointEnumerationCheck.run({
      target: {
        ...baseEndpointTarget,
        auth: "unauthenticated",
        fromFindingId: priorFinding.id,
      },
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.refuted).toHaveLength(1);
    expect(result.refuted[0].findingId).toBe(priorFinding.id);
    expect(result.confirmed).toHaveLength(0);
  });

  it("confirms prior finding when auth-required endpoint is accessible", async () => {
    const priorFinding: Finding = {
      id: "RULE-AUTH-002",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Endpoint may lack auth",
      description: "Static analysis suspects missing auth",
      evidence: [],
      remediation: "Add auth middleware",
      references: [],
      layer: "rules",
    };

    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000/api/user" },
        response: { status: 200, headers: {}, body: '{"data":"sensitive"}' },
      },
    ]);

    const result = await endpointEnumerationCheck.run({
      target: {
        ...baseEndpointTarget,
        auth: "required",
        fromFindingId: priorFinding.id,
      },
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe(priorFinding.id);
    expect(result.refuted).toHaveLength(0);

    const finding = result.findings[0];
    expect(finding.confirms).toBe(priorFinding.id);
    expect(finding.severity).toBe("high");
    expect(finding.cwe).toBe("CWE-306");
  });
});
