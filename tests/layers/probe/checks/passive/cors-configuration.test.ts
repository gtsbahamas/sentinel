import { describe, it, expect } from "vitest";
import { corsConfigurationCheck } from "../../../../../src/layers/probe/checks/passive/cors-configuration.js";
import { MockHttpClient } from "../../../../../src/layers/probe/http-client.js";
import { ProbeCleanupRegistry } from "../../../../../src/layers/probe/cleanup-registry.js";
import type { ProbeTarget, ProjectModel } from "../../../../../src/model/types.js";

function emptyModel(): ProjectModel {
  return {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [], endpoints: [], fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

const endpointTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/v1/data",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "recon",
};

const baselineTarget: ProbeTarget = {
  kind: "baseline",
  url: "https://example.com",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "recon",
};

describe("cors-configuration check", () => {
  it("applies only to endpoint targets", () => {
    expect(corsConfigurationCheck.appliesTo(endpointTarget, emptyModel())).toBe(true);
    expect(corsConfigurationCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("detects wildcard CORS with credentials as critical", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "https://api.example.com/v1/data" },
        response: {
          status: 200,
          headers: {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
          },
          body: "",
        },
      },
    ]);

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.findings[0].domain).toBe("api-security");
    expect(result.findings[0].layer).toBe("probe");
  });

  it("detects origin reflection with credentials as high", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "https://api.example.com/v1/data" },
        response: {
          status: 200,
          headers: {
            "access-control-allow-origin": "https://sentinel-cors-probe.example.com",
            "access-control-allow-credentials": "true",
          },
          body: "",
        },
      },
    ]);

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].domain).toBe("api-security");
  });

  it("detects origin reflection without credentials as medium", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "https://api.example.com/v1/data" },
        response: {
          status: 200,
          headers: {
            "access-control-allow-origin": "https://sentinel-cors-probe.example.com",
          },
          body: "",
        },
      },
    ]);

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("medium");
    expect(result.findings[0].domain).toBe("api-security");
  });

  it("refutes prior CORS finding when origin is not reflected", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "https://api.example.com/v1/data" },
        response: {
          status: 200,
          headers: {
            "access-control-allow-origin": "https://myapp.com",
          },
          body: "",
        },
      },
    ]);

    const priorFinding = {
      id: "RULE-CORS-001",
      domain: "api-security" as const,
      severity: "high" as const,
      confidence: "medium" as const,
      title: "Potential CORS misconfiguration",
      description: "Static analysis detected possible CORS issue",
      evidence: [{ file: "next.config.js" }],
      remediation: "",
      references: [],
      layer: "rules" as const,
      ruleId: "CORS-001",
    };

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.refuted).toHaveLength(1);
    expect(result.refuted[0].findingId).toBe("RULE-CORS-001");
    // Also produces an info finding documenting the refutation
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].refutes).toBe("RULE-CORS-001");
  });

  it("produces no findings and no refutations on safe CORS without prior finding", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "https://api.example.com/v1/data" },
        response: {
          status: 200,
          headers: {
            "access-control-allow-origin": "https://myapp.com",
          },
          body: "",
        },
      },
    ]);

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
  });
});
