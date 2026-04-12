import { describe, it, expect, vi, afterEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { Finding, ProjectModel } from "../../src/model/types.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("probe: finding confirmation", () => {
  it("upgrades a rules finding about missing HSTS to confirmed", async () => {
    // Mock fetch to return 200 with NO security headers
    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html></html>",
    });
    vi.stubGlobal("fetch", mockFetch);

    const priorFinding: Finding = {
      id: "INFRA-HSTS-001",
      domain: "infrastructure" as const,
      severity: "high" as const,
      confidence: "medium" as const,
      title: "Missing strict-transport-security header",
      description: "No HSTS header configured",
      evidence: [{ file: "next.config.js" }],
      remediation: "Add HSTS header",
      references: [],
      layer: "rules" as const,
    };

    // Empty model — no endpoints needed; the baseline target alone triggers security-headers check
    const model: ProjectModel = {
      meta: {
        name: "test",
        rootDir: "/tmp/test",
        stack: "nextjs-supabase",
        language: "typescript",
        framework: "nextjs",
        packageManager: "npm",
        hasDockerfile: false,
        hasCIConfig: false,
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
        cloud: [],
        rateLimit: false,
        waf: false,
        cdn: false,
        edgeFunctions: false,
      },
      findings: [],
    };

    const config = {
      ...PROBE_CONFIG_DEFAULTS,
      enabled: true,
      targetUrl: "http://localhost:3000",
      allowPublicHosts: true,
    };

    const { result, mergedFindings } = await runProbe(model, [priorFinding], config);

    // result.confirmedFindingIds must contain "INFRA-HSTS-001"
    expect(result.confirmedFindingIds).toContain("INFRA-HSTS-001");

    // The merged finding with id "INFRA-HSTS-001" must have confidence "confirmed"
    const merged = mergedFindings.find((f) => f.id === "INFRA-HSTS-001");
    expect(merged).toBeDefined();
    expect(merged!.confidence).toBe("confirmed");
  });
});
