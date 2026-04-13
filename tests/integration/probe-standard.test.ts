import { describe, it, expect, vi, afterEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { ProjectModel, ProbeConfig } from "../../src/model/types.js";

function buildJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const h = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${h}.${p}.fakesig`;
}

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
        hasAuthCheck: false,
        paramNames: [],
      },
      {
        path: "/api/users/:id",
        method: "GET",
        file: "src/app/api/users/[id]/route.ts",
        isApi: true,
        hasAuthCheck: true,
        paramNames: ["id"],
      },
      {
        path: "/api/auth/login",
        method: "POST",
        file: "src/app/api/auth/login/route.ts",
        isApi: true,
        hasAuthCheck: false,
        paramNames: [],
      },
    ],
    endpoints: [
      {
        path: "/api/users",
        method: "GET",
        file: "src/app/api/users/route.ts",
        hasAuthCheck: false,
        hasValidation: false,
        usesServiceRole: false,
      },
      {
        path: "/api/users/:id",
        method: "GET",
        file: "src/app/api/users/[id]/route.ts",
        hasAuthCheck: true,
        hasValidation: false,
        usesServiceRole: false,
      },
      {
        path: "/api/auth/login",
        method: "POST",
        file: "src/app/api/auth/login/route.ts",
        hasAuthCheck: false,
        hasValidation: false,
        usesServiceRole: false,
      },
    ],
    fileUploads: [],
    authFlows: [{ type: "login", file: "src/app/api/auth/login/route.ts" }],
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

const STANDARD_CONFIG: ProbeConfig = {
  ...PROBE_CONFIG_DEFAULTS,
  enabled: true,
  level: "standard",
  targetUrl: "http://localhost:3000",
  logDir: "/tmp/probe-test-standard",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("probe: standard level end-to-end integration", () => {
  it("runs standard checks alongside passive checks", async () => {
    const algNoneJwt = buildJwt({ alg: "none", typ: "JWT" }, { sub: "user-123", role: "admin" });
    const loginResponseBody = JSON.stringify({
      error: "User not found with that email address",
      token: algNoneJwt,
    });

    const mockFetch = vi.fn().mockImplementation(async (url: string, _init: RequestInit) => {
      const urlStr = String(url);

      // IDOR probe targets: sentinel UUIDs substituted into /api/users/:id
      if (urlStr.includes("/api/users/") && (urlStr.includes("00000000") || urlStr.includes("ffffffff"))) {
        return {
          status: 200,
          headers: new Headers({ "content-type": "application/json" }),
          text: async () => JSON.stringify({ id: "test", name: "leaked" }),
        };
      }

      // Auth login endpoint — triggers auth-endpoint-probe and jwt-claim-audit
      if (urlStr.includes("/api/auth/login")) {
        return {
          status: 401,
          headers: new Headers({ "content-type": "application/json" }),
          text: async () => loginResponseBody,
        };
      }

      // Everything else — no security headers, basic HTML
      return {
        status: 200,
        headers: new Headers({ "content-type": "text/html" }),
        text: async () => "<html><body>Hello</body></html>",
      };
    });

    vi.stubGlobal("fetch", mockFetch);

    const model = buildModel();
    const { result } = await runProbe(model, [], STANDARD_CONFIG);

    // Aggression level must be reflected in the result
    expect(result.aggressionLevel).toBe("standard");

    // Has findings from passive checks (missing security headers)
    const passiveFindings = result.findings.filter(
      (f) => f.title.toLowerCase().includes("missing security header"),
    );
    expect(passiveFindings.length).toBeGreaterThan(0);

    // Has findings from rate-limit-probe
    const rateLimitFindings = result.findings.filter(
      (f) => f.probeEvidence.checkId === "rate-limit-probe",
    );
    expect(rateLimitFindings.length).toBeGreaterThan(0);

    // Has findings from auth-endpoint-probe
    const authEndpointFindings = result.findings.filter(
      (f) => f.probeEvidence.checkId === "auth-endpoint-probe",
    );
    expect(authEndpointFindings.length).toBeGreaterThan(0);

    // Has findings from jwt-claim-audit
    const jwtAuditFindings = result.findings.filter(
      (f) => f.probeEvidence.checkId === "jwt-claim-audit",
    );
    expect(jwtAuditFindings.length).toBeGreaterThan(0);

    // Has findings from idor-probe
    const idorFindings = result.findings.filter(
      (f) => f.probeEvidence.checkId === "idor-probe",
    );
    expect(idorFindings.length).toBeGreaterThan(0);

    // Request budget respected
    expect(result.usedRequests).toBeLessThanOrEqual(result.requestCap);
    expect(result.requestCap).toBe(2000);
  });

  it("standard checks do NOT run at passive level", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html><body>Hello</body></html>",
    });

    vi.stubGlobal("fetch", mockFetch);

    const passiveConfig: ProbeConfig = {
      ...PROBE_CONFIG_DEFAULTS,
      enabled: true,
      level: "passive",
      targetUrl: "http://localhost:3000",
      logDir: "/tmp/probe-test-standard-passive",
    };

    const model = buildModel();
    const { result } = await runProbe(model, [], passiveConfig);

    expect(result.aggressionLevel).toBe("passive");

    const standardCheckIds = ["rate-limit-probe", "auth-endpoint-probe", "jwt-claim-audit", "idor-probe"];

    for (const checkId of standardCheckIds) {
      const found = result.findings.filter(
        (f) => f.probeEvidence.checkId === checkId,
      );
      expect(found).toHaveLength(0);
    }
  });
});
