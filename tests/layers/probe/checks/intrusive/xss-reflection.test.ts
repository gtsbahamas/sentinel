import { describe, it, expect } from "vitest";
import { xssReflectionCheck } from "../../../../../src/layers/probe/checks/intrusive/xss-reflection.js";
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

const queryTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/search",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "rules",
  fromFindingId: "INPUT-XSS-001",
  inputs: [{ name: "q", in: "query", type: "string" }],
};

const bodyTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/submit",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "rules",
  inputs: [{ name: "comment", in: "body", type: "string" }],
};

const noInputTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/health",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "rules",
};

const baselineTarget: ProbeTarget = {
  kind: "baseline",
  url: "https://example.com",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "recon",
};

describe("xss-reflection check", () => {
  it("appliesTo — true for endpoint with query/body inputs, false for no-input and baseline", () => {
    expect(xssReflectionCheck.appliesTo(queryTarget, emptyModel())).toBe(true);
    expect(xssReflectionCheck.appliesTo(bodyTarget, emptyModel())).toBe(true);
    expect(xssReflectionCheck.appliesTo(noInputTarget, emptyModel())).toBe(false);
    expect(xssReflectionCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("detects unescaped reflection via query param — high severity, CWE-79", async () => {
    const client = new MockHttpClient([], 2000);

    // Echo back whatever was sent in the query param
    client.request = async (req) => {
      const urlObj = new URL(req.url);
      const qVal = urlObj.searchParams.get("q") ?? "";
      return { status: 200, headers: {}, body: `<html>${qVal}</html>`, timingMs: 1, requestId: "mock-1" };
    };

    const result = await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].domain).toBe("input-injection");
    expect(result.findings[0].cwe).toBe("CWE-79");
    expect(result.findings[0].layer).toBe("probe");
    expect(result.findings[0].confidence).toBe("confirmed");
  });

  it("no high-severity finding when marker is HTML-escaped in response", async () => {
    const client = new MockHttpClient([], 2000);

    // HTML-escape the reflected value so the marker is NOT present verbatim
    client.request = async (req) => {
      const urlObj = new URL(req.url);
      const qVal = urlObj.searchParams.get("q") ?? "";
      const escaped = qVal
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
      return { status: 200, headers: {}, body: `<html>${escaped}</html>`, timingMs: 1, requestId: "mock-2" };
    };

    const result = await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it("confirms prior XSS finding when reflection is detected", async () => {
    const client = new MockHttpClient([], 2000);

    client.request = async (req) => {
      const urlObj = new URL(req.url);
      const qVal = urlObj.searchParams.get("q") ?? "";
      return { status: 200, headers: {}, body: `<html>${qVal}</html>`, timingMs: 1, requestId: "mock-3" };
    };

    const priorFinding: Finding = {
      id: "INPUT-XSS-001",
      domain: "input-injection",
      severity: "medium",
      confidence: "medium",
      title: "Potential XSS in search endpoint",
      description: "Static analysis detected unsanitized user input rendered in response",
      evidence: [{ file: "src/app/api/search/route.ts" }],
      remediation: "",
      references: [],
      layer: "rules",
      ruleId: "XSS-001",
    };

    const result = await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].confirms).toBe("INPUT-XSS-001");
    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("INPUT-XSS-001");
  });

  it("registers zero cleanup obligations", async () => {
    const client = new MockHttpClient([], 2000);

    // Safe response — no reflection
    client.request = async (_req) => {
      return { status: 200, headers: {}, body: "<html>safe</html>", timingMs: 1, requestId: "mock-4" };
    };

    const registry = new ProbeCleanupRegistry();

    await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    expect(registry.pendingCount()).toBe(0);
  });

  it("handles target unreachable gracefully — returns error, no findings", async () => {
    const client = new MockHttpClient([], 2000);

    client.request = async (_req) => {
      throw new TargetUnreachable("https://api.example.com/search");
    };

    const result = await xssReflectionCheck.run({
      target: queryTarget,
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
    expect(result.errors[0].checkId).toBe("xss-reflection");
  });
});
