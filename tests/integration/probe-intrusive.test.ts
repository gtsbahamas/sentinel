import { describe, it, expect, vi, afterEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { ProjectModel, ProbeConfig } from "../../src/model/types.js";

const INTRUSIVE_CONFIG: ProbeConfig = {
  ...PROBE_CONFIG_DEFAULTS,
  enabled: true,
  level: "intrusive",
  targetUrl: "http://localhost:3000",
  logDir: "/tmp/probe-test-intrusive",
};

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
        path: "/search",
        method: "GET",
        file: "src/app/search/page.tsx",
        isApi: false,
        hasAuthCheck: false,
        paramNames: [],
      },
      {
        path: "/api/upload",
        method: "POST",
        file: "src/app/api/upload/route.ts",
        isApi: true,
        hasAuthCheck: false,
        paramNames: [],
      },
      {
        path: "/api/upload/:id",
        method: "DELETE",
        file: "src/app/api/upload/[id]/route.ts",
        isApi: true,
        hasAuthCheck: false,
        paramNames: ["id"],
      },
      {
        path: "/api/comments",
        method: "POST",
        file: "src/app/api/comments/route.ts",
        isApi: true,
        hasAuthCheck: false,
        paramNames: [],
      },
    ],
    endpoints: [
      {
        path: "/search",
        method: "GET",
        file: "src/app/search/page.tsx",
        hasAuthCheck: false,
        hasValidation: false,
        usesServiceRole: false,
      },
      {
        path: "/api/upload",
        method: "POST",
        file: "src/app/api/upload/route.ts",
        hasAuthCheck: false,
        hasValidation: false,
        usesServiceRole: false,
      },
      {
        path: "/api/upload/:id",
        method: "DELETE",
        file: "src/app/api/upload/[id]/route.ts",
        hasAuthCheck: false,
        hasValidation: false,
        usesServiceRole: false,
      },
      {
        path: "/api/comments",
        method: "POST",
        file: "src/app/api/comments/route.ts",
        hasAuthCheck: false,
        hasValidation: false,
        usesServiceRole: false,
      },
    ],
    fileUploads: [
      {
        file: "src/app/api/upload/route.ts",
        line: 10,
        acceptsMultipart: true,
        hasMimeValidation: false,
        hasSizeLimit: false,
        usesUserFilename: true,
        storageDestination: "supabase",
      },
    ],
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

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("probe: intrusive level end-to-end integration", () => {
  it("runs intrusive checks alongside passive and standard", async () => {
    const mockFetch = vi.fn().mockImplementation(
      async (url: string, init?: RequestInit) => {
        const urlStr = String(url);
        const method = (init?.method ?? "GET").toUpperCase();

        // DELETE /api/upload/:id — cleanup succeeds
        if (method === "DELETE" && urlStr.includes("/api/upload/")) {
          return {
            status: 204,
            headers: new Headers({ "content-type": "application/json" }),
            text: async () => "",
          };
        }

        // POST /api/upload — file upload accepted (triggers file-upload findings)
        if (method === "POST" && urlStr.includes("/api/upload")) {
          return {
            status: 200,
            headers: new Headers({ "content-type": "application/json" }),
            text: async () => JSON.stringify({ id: "upload-test-123" }),
          };
        }

        // POST /api/comments — 500 with stack trace (triggers form-fuzzing findings)
        if (method === "POST" && urlStr.includes("/api/comments")) {
          return {
            status: 500,
            headers: new Headers({ "content-type": "application/json" }),
            text: async () =>
              JSON.stringify({
                error: "Internal Server Error",
                stack: "TypeError at /app/src/comments.ts:15:3",
              }),
          };
        }

        // Everything else — basic HTML, no security headers
        return {
          status: 200,
          headers: new Headers({ "content-type": "text/html" }),
          text: async () => "<html><body>Hello</body></html>",
        };
      },
    );

    vi.stubGlobal("fetch", mockFetch);

    const model = buildModel();
    const { result } = await runProbe(model, [], INTRUSIVE_CONFIG);

    // Aggression level reported correctly
    expect(result.aggressionLevel).toBe("intrusive");

    // Request cap for intrusive level is 5000
    expect(result.requestCap).toBe(5000);

    // Budget was respected
    expect(result.usedRequests).toBeLessThanOrEqual(result.requestCap);

    // Passive checks still fire (missing security headers)
    const passiveFindings = result.findings.filter((f) =>
      f.title.toLowerCase().includes("missing security header"),
    );
    expect(passiveFindings.length).toBeGreaterThan(0);

    // file-upload check fired — upload was accepted without MIME validation
    const fileUploadFindings = result.findings.filter(
      (f) => f.probeEvidence.checkId === "file-upload",
    );
    expect(fileUploadFindings.length).toBeGreaterThan(0);

    // form-fuzzing check fired — /api/comments returned 500 with stack trace
    const formFuzzingFindings = result.findings.filter(
      (f) => f.probeEvidence.checkId === "form-fuzzing",
    );
    expect(formFuzzingFindings.length).toBeGreaterThan(0);

    // Cleanup obligations from file-upload ran (one per test file: txt, png, traversal)
    expect(result.cleanupObligationsExecuted).toBeGreaterThan(0);

    // No cleanup failures — DELETE endpoint returned 204
    expect(result.cleanupObligationsFailed).toBe(0);
  });

  it("intrusive checks do NOT run at standard level", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html><body>Hello</body></html>",
    });

    vi.stubGlobal("fetch", mockFetch);

    const standardConfig: ProbeConfig = {
      ...PROBE_CONFIG_DEFAULTS,
      enabled: true,
      level: "standard",
      targetUrl: "http://localhost:3000",
      logDir: "/tmp/probe-test-intrusive-standard",
    };

    const model = buildModel();
    const { result } = await runProbe(model, [], standardConfig);

    expect(result.aggressionLevel).toBe("standard");

    const intrusiveCheckIds = ["xss-reflection", "file-upload", "form-fuzzing"];

    for (const checkId of intrusiveCheckIds) {
      const found = result.findings.filter(
        (f) => f.probeEvidence.checkId === checkId,
      );
      expect(found).toHaveLength(0);
    }
  });
});
