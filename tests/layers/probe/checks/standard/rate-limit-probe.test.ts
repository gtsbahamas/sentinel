import { describe, it, expect } from "vitest";
import { rateLimitProbeCheck } from "../../../../../src/layers/probe/checks/standard/rate-limit-probe.js";
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

const endpointTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/v1/data",
  method: "GET",
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

describe("rate-limit-probe check", () => {
  it("applies only to endpoint targets", () => {
    expect(rateLimitProbeCheck.appliesTo(endpointTarget, emptyModel())).toBe(true);
    expect(rateLimitProbeCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("confirms missing rate limit when no 429 after burst — makes exactly 20 requests", async () => {
    const client = new MockHttpClient(
      [
        {
          match: { method: "GET", url: "https://api.example.com/v1/data" },
          response: { status: 200, headers: {}, body: "ok" },
        },
      ],
      2000,
    );

    const result = await rateLimitProbeCheck.run({
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
    expect(result.findings[0].layer).toBe("probe");
    expect(result.findings[0].cwe).toBe("CWE-770");
    expect(client.requestsUsed()).toBe(20);
  });

  it("refutes when 429 received — stops early, fewer than 20 requests", async () => {
    let callCount = 0;
    const client = new MockHttpClient(
      [
        {
          match: { url: "https://api.example.com/v1/data" },
          response: { status: 200, headers: {}, body: "ok" },
        },
      ],
      2000,
    );

    // Override to return 429 on 5th request
    const originalRequest = client.request.bind(client);
    client.request = async (req) => {
      callCount++;
      if (callCount === 5) {
        return {
          status: 429,
          headers: { "retry-after": "60" },
          body: "Too Many Requests",
          timingMs: 1,
          requestId: "mock-429",
        };
      }
      return originalRequest(req);
    };

    const result = await rateLimitProbeCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("info");
    expect(result.findings[0].domain).toBe("api-security");
    expect(result.findings[0].layer).toBe("probe");
    expect(callCount).toBe(5);
    expect(callCount).toBeLessThan(20);
  });

  it("handles target unreachable gracefully — returns error, no findings", async () => {
    const client = new MockHttpClient([], 2000);
    client.request = async (_req) => {
      throw new TargetUnreachable("https://api.example.com/v1/data");
    };

    const result = await rateLimitProbeCheck.run({
      target: endpointTarget,
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
    expect(result.errors[0].checkId).toBe("rate-limit-probe");
  });

  it("produces finding even without prior finding to confirm", async () => {
    const client = new MockHttpClient(
      [
        {
          match: { method: "GET", url: "https://api.example.com/v1/data" },
          response: { status: 200, headers: {}, body: "ok" },
        },
      ],
      2000,
    );

    const result = await rateLimitProbeCheck.run({
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
    expect(result.confirmed).toHaveLength(0);
    expect(result.findings[0].confirms).toBeUndefined();
  });

  it("confirms prior finding when no 429 after burst", async () => {
    const client = new MockHttpClient(
      [
        {
          match: { method: "GET", url: "https://api.example.com/v1/data" },
          response: { status: 200, headers: {}, body: "ok" },
        },
      ],
      2000,
    );

    const priorFinding: Finding = {
      id: "RULE-RATELIMIT-001",
      domain: "api-security",
      severity: "medium",
      confidence: "medium",
      title: "Missing rate limiting on endpoint",
      description: "Static analysis detected no rate limiting configuration",
      evidence: [{ file: "src/app/api/data/route.ts" }],
      remediation: "",
      references: [],
      layer: "rules",
      ruleId: "RATE-001",
    };

    const targetWithFinding: ProbeTarget = {
      ...endpointTarget,
      fromFindingId: "RULE-RATELIMIT-001",
    };

    const result = await rateLimitProbeCheck.run({
      target: targetWithFinding,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("medium");
    expect(result.findings[0].confirms).toBe("RULE-RATELIMIT-001");
    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("RULE-RATELIMIT-001");
  });
});
