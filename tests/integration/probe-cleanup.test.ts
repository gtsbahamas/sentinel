import { describe, it, expect, vi, afterEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { ProjectModel, ProbeConfig } from "../../src/model/types.js";

function buildModel(securityHeaders: Record<string, string> = {}): ProjectModel {
  return {
    meta: {
      name: "test-app",
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
      securityHeaders,
    },
    findings: [],
  };
}

const BASE_CONFIG: ProbeConfig = {
  ...PROBE_CONFIG_DEFAULTS,
  enabled: true,
  level: "passive",
  targetUrl: "http://localhost:3000",
  logDir: "/tmp/probe-test-cleanup",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("probe: cleanup obligations integration", () => {
  it("reports zero cleanup obligations for passive-only run", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html><body>Hello</body></html>",
    });

    vi.stubGlobal("fetch", mockFetch);

    const model = buildModel();
    const { result } = await runProbe(model, [], BASE_CONFIG);

    expect(result.cleanupObligationsExecuted).toBe(0);
    expect(result.cleanupObligationsFailed).toBe(0);
    expect(result.cleanupFailures).toHaveLength(0);
  });

  it("cleanup registry is available but unused in passive mode", async () => {
    const allSecurityHeaders: Record<string, string> = {
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "content-security-policy": "default-src 'self'",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=()",
    };

    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({
        "content-type": "text/html",
        ...allSecurityHeaders,
      }),
      text: async () => "<html><body>Hello</body></html>",
    });

    vi.stubGlobal("fetch", mockFetch);

    const model = buildModel(allSecurityHeaders);
    const { result } = await runProbe(model, [], BASE_CONFIG);

    expect(result.cleanupObligationsExecuted).toBe(0);
    expect(result.cleanupObligationsFailed).toBe(0);
    expect(result.cleanupFailures).toHaveLength(0);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});
