import { describe, it, expect } from "vitest";
import { authEndpointProbeCheck } from "../../../../../src/layers/probe/checks/standard/auth-endpoint-probe.js";
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

const authPostTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/auth/login",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "recon",
};

const nonAuthGetTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/v1/products",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "recon",
};

describe("auth-endpoint-probe check", () => {
  it("appliesTo — true for POST auth endpoint, false for GET non-auth endpoint", () => {
    expect(authEndpointProbeCheck.appliesTo(authPostTarget, emptyModel())).toBe(true);
    expect(authEndpointProbeCheck.appliesTo(nonAuthGetTarget, emptyModel())).toBe(false);
  });

  it("detects verbose error messages (user enumeration) — CWE-204", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: "https://api.example.com/auth/login" },
        response: {
          status: 400,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: "User not found" }),
        },
      },
    ], 10);

    const result = await authEndpointProbeCheck.run({
      target: authPostTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const enumFinding = result.findings.find((f) => f.cwe === "CWE-204");
    expect(enumFinding).toBeDefined();
    expect(enumFinding!.severity).toBe("medium");
    expect(enumFinding!.domain).toBe("auth-access-control");
    expect(enumFinding!.layer).toBe("probe");
  });

  it("detects stack trace leakage in error responses — CWE-209", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: "https://api.example.com/auth/login" },
        response: {
          status: 500,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: "Internal error", stack: "Error: something\n    at handler (src/auth.ts:42:10)\n    at next" }),
        },
      },
    ], 10);

    const result = await authEndpointProbeCheck.run({
      target: authPostTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const stackFinding = result.findings.find((f) => f.cwe === "CWE-209");
    expect(stackFinding).toBeDefined();
    expect(stackFinding!.severity).toBe("medium");
    expect(stackFinding!.domain).toBe("auth-access-control");
    expect(stackFinding!.layer).toBe("probe");
  });

  it("produces no findings on clean generic error ('Invalid credentials')", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: "https://api.example.com/auth/login" },
        response: {
          status: 401,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: "Invalid credentials" }),
        },
      },
    ], 10);

    const result = await authEndpointProbeCheck.run({
      target: authPostTarget,
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

  it("confirms prior auth finding when verbose errors detected", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: "https://api.example.com/auth/login" },
        response: {
          status: 400,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: "Email not registered" }),
        },
      },
    ], 10);

    const priorFinding: Finding = {
      id: "RULE-AUTH-ENUM-001",
      domain: "auth-access-control",
      severity: "medium",
      confidence: "medium",
      title: "Potential user enumeration via auth endpoint",
      description: "Static analysis detected inconsistent error responses on auth endpoint",
      evidence: [{ file: "src/app/api/auth/login/route.ts" }],
      remediation: "",
      references: [],
      layer: "rules",
      ruleId: "AUTH-ENUM-001",
    };

    const result = await authEndpointProbeCheck.run({
      target: authPostTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const enumFinding = result.findings.find((f) => f.cwe === "CWE-204");
    expect(enumFinding).toBeDefined();
    expect(enumFinding!.confirms).toBe("RULE-AUTH-ENUM-001");
    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("RULE-AUTH-ENUM-001");
  });

  it("handles target unreachable gracefully — returns error, no findings", async () => {
    const client = new MockHttpClient([], 10);
    client.request = async (_req) => {
      throw new TargetUnreachable("https://api.example.com/auth/login");
    };

    const result = await authEndpointProbeCheck.run({
      target: authPostTarget,
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
    expect(result.errors[0].checkId).toBe("auth-endpoint-probe");
  });
});
