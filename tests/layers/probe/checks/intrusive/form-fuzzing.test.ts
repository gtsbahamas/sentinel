import { describe, it, expect } from "vitest";
import { formFuzzingCheck } from "../../../../../src/layers/probe/checks/intrusive/form-fuzzing.js";
import { MockHttpClient, TargetUnreachable } from "../../../../../src/layers/probe/http-client.js";
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

const postTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/comments",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "recon",
  inputs: [{ name: "body", in: "body", type: "string" }],
};

const getTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/comments",
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

describe("form-fuzzing check", () => {
  it("appliesTo — true for POST, false for GET and baseline", () => {
    expect(formFuzzingCheck.appliesTo(postTarget, emptyModel())).toBe(true);

    const putTarget: ProbeTarget = { ...postTarget, method: "PUT" };
    expect(formFuzzingCheck.appliesTo(putTarget, emptyModel())).toBe(true);

    const patchTarget: ProbeTarget = { ...postTarget, method: "PATCH" };
    expect(formFuzzingCheck.appliesTo(patchTarget, emptyModel())).toBe(true);

    expect(formFuzzingCheck.appliesTo(getTarget, emptyModel())).toBe(false);
    expect(formFuzzingCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("detects 500 server errors as medium severity (CWE-20)", async () => {
    const client = new MockHttpClient([], 5000);

    client.request = async (_req) => {
      return { status: 500, headers: {}, body: "Internal Server Error", timingMs: 1, requestId: "mock-1" };
    };

    const result = await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const serverErrorFinding = result.findings.find((f) => f.cwe === "CWE-20");
    expect(serverErrorFinding).toBeDefined();
    expect(serverErrorFinding!.severity).toBe("medium");
    expect(serverErrorFinding!.domain).toBe("business-logic");
    expect(serverErrorFinding!.layer).toBe("probe");
    expect(serverErrorFinding!.confidence).toBe("confirmed");
  });

  it("detects stack trace leakage (CWE-209)", async () => {
    const client = new MockHttpClient([], 5000);

    client.request = async (_req) => {
      return {
        status: 400,
        headers: {},
        body: 'Bad Request\n    at Object.handler (src/routes/comments.ts:42:15)\n    at processRequest (src/middleware.ts:18:5)',
        timingMs: 1,
        requestId: "mock-2",
      };
    };

    const result = await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const stackTraceFinding = result.findings.find((f) => f.cwe === "CWE-209");
    expect(stackTraceFinding).toBeDefined();
    expect(stackTraceFinding!.severity).toBe("medium");
    expect(stackTraceFinding!.domain).toBe("business-logic");
    expect(stackTraceFinding!.layer).toBe("probe");
    expect(stackTraceFinding!.confidence).toBe("confirmed");
  });

  it("no findings when all payloads return 400 with generic error", async () => {
    const client = new MockHttpClient([], 5000);

    client.request = async (_req) => {
      return { status: 400, headers: {}, body: '{"error":"Bad Request"}', timingMs: 1, requestId: "mock-3" };
    };

    const result = await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it("registers zero cleanup obligations", async () => {
    const client = new MockHttpClient([], 5000);

    client.request = async (_req) => {
      return { status: 400, headers: {}, body: '{"error":"Bad Request"}', timingMs: 1, requestId: "mock-4" };
    };

    const registry = new ProbeCleanupRegistry();

    await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    expect(registry.pendingCount()).toBe(0);
  });

  it("all requests use intent 'read'", async () => {
    const client = new MockHttpClient([], 5000);
    const recordedIntents: Array<string | undefined> = [];

    client.request = async (req) => {
      recordedIntents.push(req.intent);
      return { status: 400, headers: {}, body: '{"error":"Bad Request"}', timingMs: 1, requestId: "mock-5" };
    };

    await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(recordedIntents.length).toBeGreaterThan(0);
    expect(recordedIntents.every((intent) => intent === "read")).toBe(true);
  });

  it("handles target unreachable gracefully — returns error, no findings", async () => {
    const client = new MockHttpClient([], 5000);

    client.request = async (_req) => {
      throw new TargetUnreachable("https://api.example.com/api/comments");
    };

    const result = await formFuzzingCheck.run({
      target: postTarget,
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
    expect(result.errors[0].checkId).toBe("form-fuzzing");
  });
});
