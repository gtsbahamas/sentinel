import { describe, it, expect } from "vitest";
import { fileUploadCheck } from "../../../../../src/layers/probe/checks/intrusive/file-upload.js";
import { MockHttpClient, TargetUnreachable } from "../../../../../src/layers/probe/http-client.js";
import { ProbeCleanupRegistry } from "../../../../../src/layers/probe/cleanup-registry.js";
import type { ProbeTarget, ProjectModel } from "../../../../../src/model/types.js";
import type { HttpRequest } from "../../../../../src/layers/probe/http-client.js";

function emptyModel(): ProjectModel {
  return {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [], endpoints: [], fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

function modelWithUpload(): ProjectModel {
  const m = emptyModel();
  m.fileUploads = [{ file: "src/app/api/upload/route.ts", line: 10, acceptsMultipart: true, hasMimeValidation: false, hasSizeLimit: false, usesUserFilename: true, storageDestination: "supabase" }];
  m.endpoints = [
    { path: "/api/upload", method: "POST", file: "src/app/api/upload/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
    { path: "/api/upload/:id", method: "DELETE", file: "src/app/api/upload/[id]/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
  ];
  return m;
}

function modelWithUploadNoDelete(): ProjectModel {
  const m = emptyModel();
  m.fileUploads = [{ file: "src/app/api/upload/route.ts", line: 10, acceptsMultipart: true, hasMimeValidation: false, hasSizeLimit: false, usesUserFilename: true, storageDestination: "supabase" }];
  m.endpoints = [
    { path: "/api/upload", method: "POST", file: "src/app/api/upload/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
  ];
  return m;
}

const uploadTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/upload",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "rules",
  fromFindingId: "UPLOAD-001",
};

const nonUploadTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/users",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "rules",
};

describe("file-upload check", () => {
  it("appliesTo — true for POST upload endpoint with matching fileUpload handler, false for non-upload", () => {
    expect(fileUploadCheck.appliesTo(uploadTarget, modelWithUpload())).toBe(true);
    expect(fileUploadCheck.appliesTo(nonUploadTarget, modelWithUpload())).toBe(false);
    expect(fileUploadCheck.appliesTo(uploadTarget, emptyModel())).toBe(false);
    // GET endpoint should not apply
    const getTarget: ProbeTarget = { ...uploadTarget, method: "GET" };
    expect(fileUploadCheck.appliesTo(getTarget, modelWithUpload())).toBe(false);
  });

  it("skips entirely when no DELETE endpoint exists — zero requests, zero obligations", async () => {
    const client = new MockHttpClient([], 500);
    const registry = new ProbeCleanupRegistry();

    const result = await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUploadNoDelete(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
    expect(client.requestsUsed()).toBe(0);
    expect(registry.pendingCount()).toBe(0);
  });

  it("registers blocking cleanup obligation BEFORE uploading (verify registration order)", async () => {
    const client = new MockHttpClient([
      { match: { method: "POST", url: /upload/ }, response: { status: 200, body: JSON.stringify({ id: "file-123" }) } },
      { match: { method: "DELETE", url: /upload/ }, response: { status: 204, body: "" } },
    ], 500);

    const registry = new ProbeCleanupRegistry();
    const order: string[] = [];

    // Intercept register
    const origRegister = registry.register.bind(registry);
    registry.register = (ob: import("../../../../../src/layers/probe/cleanup-registry.js").CleanupObligation) => {
      order.push("register");
      return origRegister(ob);
    };

    // Intercept mutating requests
    const origRequest = client.request.bind(client);
    client.request = async (req: HttpRequest) => {
      if (req.intent === "mutate" && req.method === "POST") order.push("upload");
      return origRequest(req);
    };

    await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    // There should be at least one register before at least one upload
    const firstRegister = order.indexOf("register");
    const firstUpload = order.indexOf("upload");
    expect(firstRegister).toBeGreaterThanOrEqual(0);
    expect(firstUpload).toBeGreaterThanOrEqual(0);
    expect(firstRegister).toBeLessThan(firstUpload);
  });

  it("cleanup obligation calls DELETE on the upload endpoint with the returned ID", async () => {
    const deletedUrls: string[] = [];

    const client = new MockHttpClient([], 500);
    client.request = async (req: HttpRequest) => {
      if (req.method === "DELETE") deletedUrls.push(req.url);
      if (req.method === "POST") {
        return { status: 200, headers: {}, body: JSON.stringify({ id: "file-abc" }), timingMs: 1, requestId: "req-1" };
      }
      return { status: 204, headers: {}, body: "", timingMs: 1, requestId: "req-2" };
    };

    const registry = new ProbeCleanupRegistry();

    await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    // Execute cleanup
    await registry.executeAll();

    // At least one DELETE should have been called with the file ID
    expect(deletedUrls.some((url) => url.includes("file-abc"))).toBe(true);
  });

  it("detects missing MIME validation — medium severity, CWE-434 — when any content type accepted", async () => {
    const client = new MockHttpClient([
      { match: { method: "POST", url: /upload/ }, response: { status: 200, body: JSON.stringify({ id: "file-123" }) } },
      { match: { method: "DELETE", url: /upload/ }, response: { status: 204, body: "" } },
    ], 500);

    const result = await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    // Should have findings for non-traversal files accepted (txt + png = 2 medium findings)
    const mimeFindings = result.findings.filter((f) => f.cwe === "CWE-434");
    expect(mimeFindings.length).toBeGreaterThanOrEqual(1);
    expect(mimeFindings[0].severity).toBe("medium");
    expect(mimeFindings[0].domain).toBe("file-upload");
    expect(mimeFindings[0].layer).toBe("probe");
    expect(mimeFindings[0].confidence).toBe("confirmed");
  });

  it("detects path traversal filename accepted — high severity, CWE-22", async () => {
    const client = new MockHttpClient([
      { match: { method: "POST", url: /upload/ }, response: { status: 200, body: JSON.stringify({ id: "file-123" }) } },
      { match: { method: "DELETE", url: /upload/ }, response: { status: 204, body: "" } },
    ], 500);

    const result = await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const traversalFindings = result.findings.filter((f) => f.cwe === "CWE-22");
    expect(traversalFindings).toHaveLength(1);
    expect(traversalFindings[0].severity).toBe("high");
    expect(traversalFindings[0].domain).toBe("file-upload");
    expect(traversalFindings[0].layer).toBe("probe");
    expect(traversalFindings[0].confidence).toBe("confirmed");
  });

  it("handles target unreachable gracefully — returns error, no findings", async () => {
    const client = new MockHttpClient([], 500);
    client.request = async (_req: HttpRequest) => {
      throw new TargetUnreachable("https://api.example.com/api/upload");
    };

    const result = await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
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
    expect(result.errors[0].checkId).toBe("file-upload");
  });
});
