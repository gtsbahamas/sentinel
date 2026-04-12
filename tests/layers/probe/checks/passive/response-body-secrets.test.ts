import { describe, it, expect } from "vitest";
import { responseBodySecretsCheck } from "../../../../../src/layers/probe/checks/passive/response-body-secrets.js";
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

const baselineTarget: ProbeTarget = {
  kind: "baseline",
  url: "http://localhost:3000",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "recon",
};

describe("response-body-secrets check", () => {
  it("applies to baseline and endpoint targets", () => {
    expect(responseBodySecretsCheck.appliesTo(baselineTarget, emptyModel())).toBe(true);
    const ep: ProbeTarget = { ...baselineTarget, kind: "endpoint" };
    expect(responseBodySecretsCheck.appliesTo(ep, emptyModel())).toBe(true);
  });

  it("detects AWS access key in response body", async () => {
    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000" },
        response: {
          status: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ key: "AKIAIOSFODNN7EXAMPLE", region: "us-east-1" }),
        },
      },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);

    const awsFinding = result.findings.find((f) => f.title.includes("AWS Access Key"));
    expect(awsFinding).toBeDefined();
    expect(awsFinding!.severity).toBe("critical");
    expect(awsFinding!.probeEvidence?.response?.bodyPreview).toBe("[REDACTED — contains secrets]");
  });

  it("detects JWT token in response body", async () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000" },
        response: {
          status: 200,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: jwt }),
        },
      },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const jwtFinding = result.findings.find((f) => f.title.includes("JWT Token") || f.title.includes("Supabase Service Role Key"));
    expect(jwtFinding).toBeDefined();
    // JWT pattern is medium; Supabase pattern is critical — the JWT we used starts with the Supabase prefix
    // so we just check it was detected, not the exact severity
    expect(["medium", "critical"]).toContain(jwtFinding!.severity);
  });

  it("detects private key block in response body", async () => {
    const body = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtEsHAqanOIONFqVaHGUFxZ0w",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");

    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000" },
        response: {
          status: 200,
          headers: { "content-type": "text/plain" },
          body,
        },
      },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);

    const keyFinding = result.findings.find((f) => f.title.includes("Private Key Block"));
    expect(keyFinding).toBeDefined();
    expect(keyFinding!.severity).toBe("critical");
  });

  it("produces no findings for clean response body", async () => {
    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000" },
        response: {
          status: 200,
          headers: { "content-type": "text/html" },
          body: "<html><body><h1>Hello World</h1></body></html>",
        },
      },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it("never returns confirm or refute (confirmed and refuted arrays are always empty)", async () => {
    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000" },
        response: {
          status: 200,
          headers: {},
          body: "AKIAIOSFODNN7EXAMPLE some content here",
        },
      },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.confirmed).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
  });
});
