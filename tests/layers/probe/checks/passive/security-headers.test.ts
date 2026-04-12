import { describe, it, expect } from "vitest";
import { securityHeadersCheck } from "../../../../../src/layers/probe/checks/passive/security-headers.js";
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

const baselineTarget: ProbeTarget = { kind: "baseline", url: "http://localhost:3000", method: "GET", auth: "unauthenticated", fromLayer: "recon" };

describe("security-headers check", () => {
  it("applies to baseline and endpoint targets", () => {
    expect(securityHeadersCheck.appliesTo(baselineTarget, emptyModel())).toBe(true);
    const ep: ProbeTarget = { ...baselineTarget, kind: "endpoint" };
    expect(securityHeadersCheck.appliesTo(ep, emptyModel())).toBe(true);
  });

  it("reports missing security headers", async () => {
    const client = new MockHttpClient([
      { match: { url: "http://localhost:3000" }, response: { status: 200, headers: { "content-type": "text/html" }, body: "<html></html>" } },
    ]);

    const result = await securityHeadersCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings.length).toBeGreaterThanOrEqual(5);
    expect(result.findings.every((f) => f.layer === "probe")).toBe(true);
    expect(result.findings.every((f) => f.confidence === "confirmed")).toBe(true);

    const hsts = result.findings.find((f) => f.title.includes("strict-transport-security"));
    expect(hsts).toBeDefined();
    expect(hsts!.severity).toBe("high");
  });

  it("produces no findings when all headers present", async () => {
    const client = new MockHttpClient([
      {
        match: { url: "http://localhost:3000" },
        response: {
          status: 200,
          headers: {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=()",
          },
          body: "",
        },
      },
    ]);

    const result = await securityHeadersCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    const nonInfoFindings = result.findings.filter((f) => f.severity !== "info");
    expect(nonInfoFindings).toHaveLength(0);
  });

  it("confirms prior findings about missing headers", async () => {
    const client = new MockHttpClient([
      { match: { url: "http://localhost:3000" }, response: { status: 200, headers: {}, body: "" } },
    ]);

    const priorFinding = {
      id: "RULE-HDR-001",
      domain: "infrastructure" as const,
      severity: "medium" as const,
      confidence: "medium" as const,
      title: "Missing content-security-policy header",
      description: "",
      evidence: [{ file: "next.config.js" }],
      remediation: "",
      references: [],
      layer: "rules" as const,
    };

    const result = await securityHeadersCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.confirmed.length).toBeGreaterThanOrEqual(1);
    const cspConfirm = result.confirmed.find((c) => c.findingId === "RULE-HDR-001");
    expect(cspConfirm).toBeDefined();
  });

  it("handles target unreachable gracefully", async () => {
    const client = new MockHttpClient([]);
    Object.defineProperty(client, "request", {
      value: async () => { throw Object.assign(new Error("connect refused"), { name: "TargetUnreachable" }); },
    });

    const result = await securityHeadersCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(1);
    expect(result.findings).toHaveLength(0);
  });
});
