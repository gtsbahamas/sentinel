import { describe, it, expect } from "vitest";
import { tlsConfigurationCheck } from "../../../../../src/layers/probe/checks/passive/tls-configuration.js";
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

describe("tls-configuration check", () => {
  it("has correct metadata", () => {
    expect(tlsConfigurationCheck.id).toBe("tls-configuration");
    expect(tlsConfigurationCheck.level).toBe("passive");
    expect(tlsConfigurationCheck.domain).toBe("cryptography");
  });

  it("applies only to HTTPS baseline targets", () => {
    const httpsBaseline: ProbeTarget = {
      kind: "baseline",
      url: "https://example.com",
      method: "GET",
      auth: "unauthenticated",
      fromLayer: "recon",
    };
    expect(tlsConfigurationCheck.appliesTo(httpsBaseline, emptyModel())).toBe(true);

    const httpBaseline: ProbeTarget = {
      kind: "baseline",
      url: "http://example.com",
      method: "GET",
      auth: "unauthenticated",
      fromLayer: "recon",
    };
    expect(tlsConfigurationCheck.appliesTo(httpBaseline, emptyModel())).toBe(false);

    const httpsEndpoint: ProbeTarget = {
      kind: "endpoint",
      url: "https://example.com/api/data",
      method: "GET",
      auth: "unauthenticated",
      fromLayer: "recon",
    };
    expect(tlsConfigurationCheck.appliesTo(httpsEndpoint, emptyModel())).toBe(false);
  });

  it("returns error when TLS handshake fails (non-routable address)", async () => {
    const unreachableTarget: ProbeTarget = {
      kind: "baseline",
      url: "https://192.0.2.1:9999",
      method: "GET",
      auth: "unauthenticated",
      fromLayer: "recon",
    };

    const result = await tlsConfigurationCheck.run({
      target: unreachableTarget,
      model: emptyModel(),
      client: new MockHttpClient([]),
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(1);
    expect(["target-unreachable", "check-error"]).toContain(result.errors[0].kind);
    expect(result.errors[0].checkId).toBe("tls-configuration");
    expect(result.findings).toHaveLength(0);
  }, 15_000);
});
