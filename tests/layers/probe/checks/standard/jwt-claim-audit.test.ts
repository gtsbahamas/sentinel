import { describe, it, expect } from "vitest";
import { jwtClaimAuditCheck } from "../../../../../src/layers/probe/checks/standard/jwt-claim-audit.js";
import { MockHttpClient, TargetUnreachable } from "../../../../../src/layers/probe/http-client.js";
import { ProbeCleanupRegistry } from "../../../../../src/layers/probe/cleanup-registry.js";
import type { ProbeTarget, ProjectModel, Finding } from "../../../../../src/model/types.js";

function emptyModel(): ProjectModel {
  return {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [], endpoints: [], fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

function buildJwt(header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const h = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${h}.${p}.fakesignature`;
}

const endpointTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/auth/login",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "recon",
};

const baselineTarget: ProbeTarget = {
  kind: "baseline",
  url: "https://example.com",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "recon",
};

describe("jwt-claim-audit check", () => {
  it("applies to endpoint targets, not baseline", () => {
    expect(jwtClaimAuditCheck.appliesTo(endpointTarget, emptyModel())).toBe(true);
    expect(jwtClaimAuditCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("detects alg:none as critical severity finding", async () => {
    const jwt = buildJwt({ alg: "none", typ: "JWT" }, { sub: "user-1", iat: 1700000000 });
    const client = new MockHttpClient(
      [
        {
          match: { url: "https://api.example.com/api/auth/login" },
          response: { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ token: jwt }) },
        },
      ],
      2000,
    );

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const algNoneFindings = result.findings.filter((f) => f.title.includes("alg:none"));
    expect(algNoneFindings).toHaveLength(1);
    expect(algNoneFindings[0].severity).toBe("critical");
    expect(algNoneFindings[0].domain).toBe("cryptography");
    expect(algNoneFindings[0].layer).toBe("probe");
    expect(algNoneFindings[0].cwe).toBe("CWE-327");
  });

  it("detects missing exp claim as medium severity finding", async () => {
    const jwt = buildJwt({ alg: "RS256", typ: "JWT" }, { sub: "user-1", iat: 1700000000 });
    const client = new MockHttpClient(
      [
        {
          match: { url: "https://api.example.com/api/auth/login" },
          response: { status: 200, headers: {}, body: JSON.stringify({ token: jwt }) },
        },
      ],
      2000,
    );

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const noExpFindings = result.findings.filter((f) => f.title.includes("missing exp"));
    expect(noExpFindings).toHaveLength(1);
    expect(noExpFindings[0].severity).toBe("medium");
    expect(noExpFindings[0].domain).toBe("cryptography");
    expect(noExpFindings[0].cwe).toBe("CWE-613");
  });

  it("detects sensitive data in claims as high severity finding", async () => {
    const jwt = buildJwt(
      { alg: "RS256", typ: "JWT" },
      { sub: "user-1", exp: 9999999999, ssn: "123-45-6789" },
    );
    const client = new MockHttpClient(
      [
        {
          match: { url: "https://api.example.com/api/auth/login" },
          response: { status: 200, headers: {}, body: JSON.stringify({ token: jwt }) },
        },
      ],
      2000,
    );

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const sensitiveFindings = result.findings.filter((f) => f.title.includes("sensitive claims"));
    expect(sensitiveFindings).toHaveLength(1);
    expect(sensitiveFindings[0].severity).toBe("high");
    expect(sensitiveFindings[0].domain).toBe("cryptography");
    expect(sensitiveFindings[0].cwe).toBe("CWE-312");
    expect(sensitiveFindings[0].description).toContain("ssn");
  });

  it("produces no findings for a well-configured JWT (RS256, exp present, standard claims)", async () => {
    const jwt = buildJwt(
      { alg: "RS256", typ: "JWT" },
      { sub: "user-1", iat: 1700000000, exp: 9999999999, name: "Alice" },
    );
    const client = new MockHttpClient(
      [
        {
          match: { url: "https://api.example.com/api/auth/login" },
          response: { status: 200, headers: {}, body: JSON.stringify({ token: jwt }) },
        },
      ],
      2000,
    );

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
    expect(result.confirmed).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
  });

  it("produces no findings when response contains no JWTs", async () => {
    const client = new MockHttpClient(
      [
        {
          match: { url: "https://api.example.com/api/auth/login" },
          response: { status: 200, headers: {}, body: JSON.stringify({ message: "ok", session_id: "abc123" }) },
        },
      ],
      2000,
    );

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
    expect(result.confirmed).toHaveLength(0);
  });

  it("confirms prior cryptography finding when alg:none is detected", async () => {
    const jwt = buildJwt({ alg: "none", typ: "JWT" }, { sub: "user-1", exp: 9999999999 });
    const client = new MockHttpClient(
      [
        {
          match: { url: "https://api.example.com/api/auth/login" },
          response: { status: 200, headers: {}, body: JSON.stringify({ token: jwt }) },
        },
      ],
      2000,
    );

    const priorFinding: Finding = {
      id: "RULE-CRYPTO-001",
      domain: "cryptography",
      severity: "high",
      confidence: "medium",
      title: "JWT algorithm not enforced",
      description: "No explicit algorithm allowlist found in JWT verification",
      evidence: [{ file: "src/lib/auth.ts" }],
      remediation: "Enforce an algorithm allowlist",
      references: [],
      layer: "rules",
      ruleId: "CRYPTO-001",
    };

    const targetWithFinding: ProbeTarget = {
      ...endpointTarget,
      fromFindingId: "RULE-CRYPTO-001",
    };

    const result = await jwtClaimAuditCheck.run({
      target: targetWithFinding,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const algNoneFindings = result.findings.filter((f) => f.title.includes("alg:none"));
    expect(algNoneFindings).toHaveLength(1);
    expect(algNoneFindings[0].confirms).toBe("RULE-CRYPTO-001");
    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("RULE-CRYPTO-001");
  });

  it("handles target unreachable gracefully — returns error, no findings", async () => {
    const client = new MockHttpClient([], 2000);
    client.request = async (_req) => {
      throw new TargetUnreachable("https://api.example.com/api/auth/login");
    };

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.confirmed).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].kind).toBe("target-unreachable");
    expect(result.errors[0].checkId).toBe("jwt-claim-audit");
  });
});
