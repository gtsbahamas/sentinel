import { describe, it, expect } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { Finding, ProjectModel, ProbeConfig } from "../../src/model/types.js";

function emptyModel(): ProjectModel {
  return {
    meta: {
      name: "test",
      path: "/test",
      stack: "nextjs-supabase",
      packageManager: "npm",
      language: "typescript",
      framework: "next",
      deployTarget: null,
    },
    routes: [],
    endpoints: [],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: {
      nextConfig: null,
      middleware: null,
      vercelConfig: null,
      supabaseConfig: null,
      securityHeaders: {},
    },
    findings: [],
  };
}

function makeProbeConfig(overrides: Partial<ProbeConfig> = {}): ProbeConfig {
  return {
    ...PROBE_CONFIG_DEFAULTS,
    enabled: true,
    targetUrl: "http://localhost:3000",
    logDir: "/tmp/sentinel-test-probe-refute",
    ...overrides,
  };
}

const priorCspFinding: Finding = {
  id: "INFRA-CSP-001",
  domain: "infrastructure" as const,
  severity: "medium" as const,
  confidence: "medium" as const,
  title: "Missing content-security-policy header",
  description: "CSP not configured",
  evidence: [{ file: "next.config.js" }],
  remediation: "Add CSP",
  references: [],
  layer: "rules" as const,
};

describe("probe refutation integration", () => {
  it("refutes a rules finding about missing CSP when header is present", async () => {
    const originalFetch = globalThis.fetch;

    globalThis.fetch = async (_input: string | URL | Request, _init?: RequestInit) => {
      return {
        status: 200,
        headers: new Headers({
          "content-security-policy": "default-src 'self'",
          "strict-transport-security": "max-age=31536000",
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
          "referrer-policy": "strict-origin",
          "permissions-policy": "camera=()",
        }),
        text: async () => "<html></html>",
      } as unknown as Response;
    };

    try {
      const model = emptyModel();
      const config = makeProbeConfig();
      const { result, mergedFindings } = await runProbe(model, [priorCspFinding], config);

      // The probe should have refuted INFRA-CSP-001 because CSP header IS present
      expect(result.refutedFindingIds).toContain("INFRA-CSP-001");

      // The merged finding with that id should have confidence "low" and refutedByProbe === true
      const merged = mergedFindings.find((f) => f.id === "INFRA-CSP-001");
      expect(merged).toBeDefined();
      expect(merged!.confidence).toBe("low");
      expect((merged as any).refutedByProbe).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
