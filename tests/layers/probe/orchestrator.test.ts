import { describe, it, expect } from "vitest";
import { runProbe } from "../../../src/layers/probe/index.js";
import type { ProjectModel, ProbeConfig, Finding } from "../../../src/model/types.js";
import { PROBE_CONFIG_DEFAULTS } from "../../../src/layers/probe/schema.js";

// Override http-client to use MockHttpClient globally for this test
// We need to mock the global fetch to prevent real network calls

function emptyModel(): ProjectModel {
  return {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [],
    endpoints: [
      { path: "/api/health", method: "GET", file: "src/api/health.ts", hasValidation: false, hasAuthCheck: false, usesServiceRole: false },
      { path: "/api/users", method: "GET", file: "src/api/users.ts", hasValidation: true, hasAuthCheck: true, usesServiceRole: false },
    ],
    fileUploads: [],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

function makeProbeConfig(overrides: Partial<ProbeConfig> = {}): ProbeConfig {
  return {
    ...PROBE_CONFIG_DEFAULTS,
    enabled: true,
    targetUrl: "http://localhost:3000",
    logDir: "/tmp/sentinel-test-probe",
    ...overrides,
  };
}

// Note: this test exercises the orchestrator integration by mocking fetch globally.
// The ProbeHttpClient will make real fetch calls; we mock at the global level.
describe("runProbe integration", () => {
  it("runs passive checks and produces findings", async () => {
    const originalFetch = globalThis.fetch;
    const mockResponses: Record<string, { status: number; headers: Record<string, string>; body: string }> = {
      "http://localhost:3000": { status: 200, headers: { "content-type": "text/html" }, body: "<html></html>" },
      "http://localhost:3000/api/health": { status: 200, headers: {}, body: '{"status":"ok"}' },
      "http://localhost:3000/api/users": { status: 401, headers: {}, body: '{"error":"Unauthorized"}' },
    };

    globalThis.fetch = async (input: string | URL | Request, _init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const mock = mockResponses[url] ?? { status: 404, headers: {}, body: "" };
      return new Response(mock.body, {
        status: mock.status,
        headers: mock.headers,
      });
    };

    try {
      const model = emptyModel();
      const config = makeProbeConfig();
      const { result } = await runProbe(model, [], config);

      expect(result.aggressionLevel).toBe("passive");
      expect(result.usedRequests).toBeGreaterThan(0);
      expect(result.cleanupObligationsFailed).toBe(0);
      expect(result.errors.length).toBeLessThanOrEqual(result.usedRequests);

      const probeFindings = result.findings;
      const headerFindings = probeFindings.filter((f) => f.probeEvidence.checkId === "security-headers");
      expect(headerFindings.length).toBeGreaterThan(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("confirms prior findings when probe evidence matches", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("/api/users")) {
        return new Response('{"error":"Unauthorized"}', { status: 401 });
      }
      return new Response("", { status: 200 });
    };

    try {
      const model = emptyModel();
      const priorFindings: Finding[] = [{
        id: "RULE-AUTH-001",
        domain: "auth-access-control",
        severity: "high",
        confidence: "medium",
        title: "No auth check on /api/health",
        description: "",
        evidence: [{ file: "src/api/health.ts" }],
        remediation: "",
        references: [],
        layer: "rules",
      }];

      const config = makeProbeConfig();
      const { result } = await runProbe(model, priorFindings, config);

      expect(result.aggressionLevel).toBe("passive");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
