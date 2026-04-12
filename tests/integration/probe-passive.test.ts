import { describe, it, expect, vi, afterEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { ProjectModel, ProbeConfig } from "../../src/model/types.js";

// Minimal ProjectModel with one endpoint so endpoint checks run.
function buildModel(): ProjectModel {
  return {
    meta: {
      name: "test-project",
      path: "/tmp/test-project",
      stack: "nextjs-supabase",
      packageManager: "npm",
      language: "typescript",
      framework: "next",
      deployTarget: null,
    },
    routes: [
      {
        path: "/api/users",
        method: "GET",
        file: "src/app/api/users/route.ts",
        isApi: true,
        hasAuthCheck: true,
        paramNames: [],
      },
    ],
    endpoints: [
      {
        path: "/api/users",
        method: "GET",
        file: "src/app/api/users/route.ts",
        hasAuthCheck: true,
        hasValidation: false,
        usesServiceRole: false,
      },
    ],
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

const BASE_CONFIG: ProbeConfig = {
  ...PROBE_CONFIG_DEFAULTS,
  enabled: true,
  level: "passive",
  targetUrl: "http://localhost:3000",
  logDir: "/tmp/probe-test-passive",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("probe: passive end-to-end integration", () => {
  it("runs all passive checks and produces findings", async () => {
    // Minimal response with no security headers — should trigger multiple findings.
    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html><body>Hello</body></html>",
    });

    vi.stubGlobal("fetch", mockFetch);

    const model = buildModel();
    const { result } = await runProbe(model, [], BASE_CONFIG);

    // Security headers check should fire at least for the baseline target.
    expect(result.findings.length).toBeGreaterThan(0);

    // Should have found at least one missing security header.
    const headerFindings = result.findings.filter((f) =>
      f.title.toLowerCase().includes("missing security header"),
    );
    expect(headerFindings.length).toBeGreaterThan(0);

    // Aggression level must be reflected in the result.
    expect(result.aggressionLevel).toBe("passive");

    // At least one request was made.
    expect(result.usedRequests).toBeGreaterThan(0);

    // Log path must follow the probe-log- naming convention.
    expect(result.probeLogPath).toContain("probe-log-");
  });

  it("uses zero requests when target is unreachable", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));

    vi.stubGlobal("fetch", mockFetch);

    const model = buildModel();
    const { result } = await runProbe(model, [], BASE_CONFIG);

    // Every check should have failed with a target-unreachable error.
    expect(result.errors.length).toBeGreaterThan(0);

    // No probe findings should be produced when the target is unreachable.
    expect(result.findings).toHaveLength(0);
  });
});
