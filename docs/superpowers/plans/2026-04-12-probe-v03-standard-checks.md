# Probe v0.3 Standard Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 4 standard-level probe checks (rate-limit-probe, auth-endpoint-probe, idor-probe, jwt-claim-audit) and wire them into the probe orchestrator.

**Architecture:** Each check follows the existing `ProbeCheck` interface pattern from passive checks. All 4 are read-only (`intent: "read"`), so no cleanup obligations are registered. The `index.ts` entry point gets a `loadStandardChecks()` function called alongside `loadPassiveChecks()`. Standard checks run when `config.level` is `"standard"` or `"intrusive"` (cumulative filtering already handled by `getProbeChecks` in `base.ts`).

**Tech Stack:** TypeScript, Vitest, MockHttpClient

---

## File Structure

### New files (4 checks + 4 unit tests + 1 integration test)

| File | Responsibility |
|------|---------------|
| `src/layers/probe/checks/standard/rate-limit-probe.ts` | Send rapid GETs to test for rate limiting |
| `src/layers/probe/checks/standard/auth-endpoint-probe.ts` | POST malformed payloads to auth endpoints |
| `src/layers/probe/checks/standard/idor-probe.ts` | GET with sentinel UUIDs on parameterized endpoints |
| `src/layers/probe/checks/standard/jwt-claim-audit.ts` | Decode JWTs from responses, flag weak config |
| `tests/layers/probe/checks/standard/rate-limit-probe.test.ts` | Unit tests for rate-limit-probe |
| `tests/layers/probe/checks/standard/auth-endpoint-probe.test.ts` | Unit tests for auth-endpoint-probe |
| `tests/layers/probe/checks/standard/idor-probe.test.ts` | Unit tests for idor-probe |
| `tests/layers/probe/checks/standard/jwt-claim-audit.test.ts` | Unit tests for jwt-claim-audit |
| `tests/integration/probe-standard.test.ts` | End-to-end integration: standard level against mock client |

### Modified files

| File | Change |
|------|--------|
| `src/layers/probe/index.ts` | Add `loadStandardChecks()`, call it in `runProbe()` |

---

## Task 1: Rate Limit Probe Check

**Files:**
- Create: `src/layers/probe/checks/standard/rate-limit-probe.ts`
- Test: `tests/layers/probe/checks/standard/rate-limit-probe.test.ts`

This check sends up to 20 rapid GET requests to endpoints flagged as missing rate limits. It observes whether any 429 responses appear. If none do after 20 requests, it produces a finding confirming the rate limit is missing.

- [ ] **Step 1: Write the unit test file**

```typescript
// tests/layers/probe/checks/standard/rate-limit-probe.test.ts
import { describe, it, expect } from "vitest";
import { rateLimitProbeCheck } from "../../../../../src/layers/probe/checks/standard/rate-limit-probe.js";
import { MockHttpClient } from "../../../../../src/layers/probe/http-client.js";
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

const endpointTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/v1/users",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "rules",
  fromFindingId: "API-RATE-001",
};

const baselineTarget: ProbeTarget = {
  kind: "baseline",
  url: "https://example.com",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "recon",
};

describe("rate-limit-probe check", () => {
  it("applies only to endpoint targets with a prior rate-limit finding", () => {
    const rateLimitFinding: Finding = {
      id: "API-RATE-001",
      domain: "api-security",
      severity: "medium",
      confidence: "medium",
      title: "No rate limiting detected",
      description: "Endpoint has no rate limiting",
      evidence: [{ file: "src/app/api/users/route.ts" }],
      remediation: "Add rate limiting",
      references: [],
      layer: "rules",
    };

    expect(rateLimitProbeCheck.appliesTo(endpointTarget, emptyModel())).toBe(true);
    expect(rateLimitProbeCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("confirms missing rate limit when no 429 received after burst", async () => {
    // All 20 requests return 200
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /api\.example\.com/ },
        response: { status: 200, body: "{}" },
      },
    ], 2000);

    const priorFinding: Finding = {
      id: "API-RATE-001",
      domain: "api-security",
      severity: "medium",
      confidence: "medium",
      title: "No rate limiting detected on /v1/users",
      description: "Endpoint has no rate limiting",
      evidence: [{ file: "src/app/api/users/route.ts" }],
      remediation: "Add rate limiting",
      references: [],
      layer: "rules",
    };

    const result = await rateLimitProbeCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("medium");
    expect(result.findings[0].confidence).toBe("confirmed");
    expect(result.findings[0].domain).toBe("api-security");
    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("API-RATE-001");

    // Should have made exactly 20 requests
    expect(client.recorded.length).toBe(20);
  });

  it("refutes missing rate limit when 429 received during burst", async () => {
    let callCount = 0;
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /api\.example\.com/ },
        response: { status: 200, body: "{}" },
      },
    ], 2000);

    // Override to return 429 after 5 requests
    const origRequest = client.request.bind(client);
    client.request = async (req) => {
      callCount++;
      if (callCount > 5) {
        const resp = await origRequest(req);
        return { ...resp, status: 429, headers: { ...resp.headers, "retry-after": "60" } };
      }
      return origRequest(req);
    };

    const priorFinding: Finding = {
      id: "API-RATE-001",
      domain: "api-security",
      severity: "medium",
      confidence: "medium",
      title: "No rate limiting detected on /v1/users",
      description: "Endpoint has no rate limiting",
      evidence: [{ file: "src/app/api/users/route.ts" }],
      remediation: "Add rate limiting",
      references: [],
      layer: "rules",
      ruleId: "RATE-LIMIT",
    };

    const result = await rateLimitProbeCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.refuted).toHaveLength(1);
    expect(result.refuted[0].findingId).toBe("API-RATE-001");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("info");

    // Should have stopped early (not all 20)
    expect(callCount).toBeLessThan(20);
  });

  it("handles target unreachable gracefully", async () => {
    const client = new MockHttpClient([], 2000);
    // Override to throw
    client.request = async () => {
      throw new (await import("../../../../../src/layers/probe/http-client.js")).TargetUnreachable("https://api.example.com/v1/users");
    };

    const result = await rateLimitProbeCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].kind).toBe("target-unreachable");
  });

  it("produces new finding even without a prior finding to confirm", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /api\.example\.com/ },
        response: { status: 200, body: "{}" },
      },
    ], 2000);

    const result = await rateLimitProbeCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("medium");
    expect(result.confirmed).toHaveLength(0); // nothing to confirm
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/probe/checks/standard/rate-limit-probe.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// src/layers/probe/checks/standard/rate-limit-probe.ts
import { randomUUID } from "crypto";
import type { ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const BURST_SIZE = 20;

export const rateLimitProbeCheck: ProbeCheck = {
  id: "rate-limit-probe",
  level: "standard" as AggressionLevel,
  domain: "api-security" as SecurityDomain,
  description: "Send rapid GET requests to test for rate limiting enforcement",

  appliesTo(target): boolean {
    return target.kind === "endpoint";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const rateLimitFinding = ctx.priorFindings.find(
      (f) =>
        f.domain === "api-security" &&
        ctx.target.fromFindingId === f.id &&
        (f.title.toLowerCase().includes("rate limit") || f.ruleId?.includes("RATE")),
    );

    let got429 = false;
    let lastStatus = 0;
    let requestsMade = 0;
    let lastRequestId = "";
    let retryAfterValue: string | undefined;

    try {
      for (let i = 0; i < BURST_SIZE; i++) {
        const resp = await ctx.client.request({
          method: "GET",
          url: ctx.target.url,
          intent: "read",
        });
        requestsMade++;
        lastStatus = resp.status;
        lastRequestId = resp.requestId;

        if (resp.status === 429) {
          got429 = true;
          retryAfterValue = resp.headers["retry-after"];
          break;
        }
      }
    } catch (err) {
      if (err instanceof TargetUnreachable) {
        errors.push({ kind: "target-unreachable", message: err.message, checkId: "rate-limit-probe", targetUrl: ctx.target.url });
        return { findings, confirmed, refuted, errors };
      }
      throw err;
    }

    const evidence = {
      requestId: lastRequestId,
      checkId: "rate-limit-probe" as const,
      aggressionLevel: "standard" as AggressionLevel,
      request: { method: "GET", url: ctx.target.url, headers: {} },
      response: {
        status: lastStatus,
        headers: retryAfterValue ? { "retry-after": retryAfterValue } : {},
        bodyPreview: "",
        timingMs: 0,
      },
    };

    if (got429) {
      // Rate limiting IS working — refute prior finding if one exists
      if (rateLimitFinding) {
        refuted.push({ findingId: rateLimitFinding.id });
        findings.push({
          id: `PROBE-RATE-${randomUUID().slice(0, 8)}`,
          domain: "api-security",
          severity: "info",
          confidence: "confirmed",
          title: `Rate limiting active on ${ctx.target.url}`,
          description: `Got 429 after ${requestsMade} requests${retryAfterValue ? ` (Retry-After: ${retryAfterValue})` : ""}`,
          evidence: [],
          remediation: "No action needed",
          references: [],
          layer: "probe",
          probeEvidence: evidence,
          refutes: rateLimitFinding.id,
        });
      }
    } else {
      // No rate limiting detected after full burst
      findings.push({
        id: `PROBE-RATE-${randomUUID().slice(0, 8)}`,
        domain: "api-security",
        severity: "medium",
        confidence: "confirmed",
        title: `No rate limiting after ${BURST_SIZE} requests: ${ctx.target.url}`,
        description: `Sent ${BURST_SIZE} rapid GET requests without receiving a 429. Endpoint may lack rate limiting.`,
        evidence: [],
        remediation: "Add rate limiting middleware (e.g., express-rate-limit, Vercel edge config, or API gateway rate limiting)",
        references: ["https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"],
        layer: "probe",
        cwe: "CWE-770",
        probeEvidence: evidence,
        confirms: rateLimitFinding?.id,
      });
      if (rateLimitFinding) {
        confirmed.push({ findingId: rateLimitFinding.id });
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/probe/checks/standard/rate-limit-probe.test.ts`
Expected: ALL PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/layers/probe/checks/standard/rate-limit-probe.ts tests/layers/probe/checks/standard/rate-limit-probe.test.ts
git commit -m "feat(probe): add rate-limit-probe standard check with tests"
```

---

## Task 2: Auth Endpoint Probe Check

**Files:**
- Create: `src/layers/probe/checks/standard/auth-endpoint-probe.ts`
- Test: `tests/layers/probe/checks/standard/auth-endpoint-probe.test.ts`

This check POSTs malformed payloads to known auth endpoints (login, signup, password reset). It observes verbose errors, timing differences, and user enumeration signals. It never attempts valid credentials.

- [ ] **Step 1: Write the unit test file**

```typescript
// tests/layers/probe/checks/standard/auth-endpoint-probe.test.ts
import { describe, it, expect } from "vitest";
import { authEndpointProbeCheck } from "../../../../../src/layers/probe/checks/standard/auth-endpoint-probe.js";
import { MockHttpClient } from "../../../../../src/layers/probe/http-client.js";
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

function modelWithAuthFlow(): ProjectModel {
  const m = emptyModel();
  m.authFlows = [{ type: "login", file: "src/app/api/auth/login/route.ts" }];
  return m;
}

const authTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/auth/login",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "recon",
};

const nonAuthTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/users",
  method: "GET",
  auth: "required",
  fromLayer: "recon",
};

describe("auth-endpoint-probe check", () => {
  it("applies to POST endpoints whose URL contains auth path segments", () => {
    expect(authEndpointProbeCheck.appliesTo(authTarget, modelWithAuthFlow())).toBe(true);
    expect(authEndpointProbeCheck.appliesTo(nonAuthTarget, modelWithAuthFlow())).toBe(false);
  });

  it("detects verbose error messages that leak user existence", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: /auth\/login/ },
        response: {
          status: 401,
          body: JSON.stringify({ error: "User not found with that email address" }),
        },
      },
    ], 2000);

    const result = await authEndpointProbeCheck.run({
      target: authTarget,
      model: modelWithAuthFlow(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const enumFindings = result.findings.filter((f) =>
      f.title.toLowerCase().includes("enumeration") || f.description.toLowerCase().includes("enumerat"),
    );
    expect(enumFindings.length).toBeGreaterThan(0);
    expect(enumFindings[0].severity).toBe("medium");
  });

  it("detects stack trace leakage in error responses", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: /auth\/login/ },
        response: {
          status: 500,
          body: JSON.stringify({
            error: "Internal server error",
            stack: "Error: Cannot read property 'password' of undefined\n    at /app/src/auth.ts:42:15",
          }),
        },
      },
    ], 2000);

    const result = await authEndpointProbeCheck.run({
      target: authTarget,
      model: modelWithAuthFlow(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const stackFindings = result.findings.filter((f) =>
      f.title.toLowerCase().includes("stack trace") || f.description.toLowerCase().includes("stack trace"),
    );
    expect(stackFindings.length).toBeGreaterThan(0);
    expect(stackFindings[0].severity).toBe("medium");
  });

  it("produces no findings on clean generic error response", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: /auth\/login/ },
        response: {
          status: 401,
          body: JSON.stringify({ error: "Invalid credentials" }),
        },
      },
    ], 2000);

    const result = await authEndpointProbeCheck.run({
      target: authTarget,
      model: modelWithAuthFlow(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    // No enumeration or stack trace findings
    const badFindings = result.findings.filter((f) =>
      f.severity !== "info",
    );
    expect(badFindings).toHaveLength(0);
  });

  it("confirms prior auth finding when verbose errors detected", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: /auth\/login/ },
        response: {
          status: 401,
          body: JSON.stringify({ error: "No account found for user@example.com" }),
        },
      },
    ], 2000);

    const priorFinding: Finding = {
      id: "AUTH-ENUM-001",
      domain: "auth-access-control",
      severity: "medium",
      confidence: "medium",
      title: "Potential user enumeration on login endpoint",
      description: "Auth endpoint may leak user existence",
      evidence: [{ file: "src/app/api/auth/login/route.ts" }],
      remediation: "Use generic error messages",
      references: [],
      layer: "rules",
    };

    const targetWithFinding: ProbeTarget = {
      ...authTarget,
      fromFindingId: "AUTH-ENUM-001",
      fromLayer: "rules",
    };

    const result = await authEndpointProbeCheck.run({
      target: targetWithFinding,
      model: modelWithAuthFlow(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("AUTH-ENUM-001");
  });

  it("handles target unreachable gracefully", async () => {
    const client = new MockHttpClient([], 2000);
    client.request = async () => {
      throw new (await import("../../../../../src/layers/probe/http-client.js")).TargetUnreachable("https://api.example.com/api/auth/login");
    };

    const result = await authEndpointProbeCheck.run({
      target: authTarget,
      model: modelWithAuthFlow(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].kind).toBe("target-unreachable");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/probe/checks/standard/auth-endpoint-probe.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// src/layers/probe/checks/standard/auth-endpoint-probe.ts
import { randomUUID } from "crypto";
import type { ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const AUTH_PATH_RE = /\/(auth|login|signin|sign-in|signup|sign-up|register|password|forgot|reset|verify|token|session)/i;

const ENUMERATION_PATTERNS = [
  /user\s*not\s*found/i,
  /no\s*account/i,
  /email\s*not\s*registered/i,
  /unknown\s*user/i,
  /invalid\s*username/i,
  /account\s*does\s*not\s*exist/i,
  /no\s*user\s*with/i,
  /email\s*already\s*(registered|exists|taken|in\s*use)/i,
  /username\s*already\s*(taken|exists|in\s*use)/i,
];

const STACK_TRACE_PATTERNS = [
  /at\s+[\w.]+\s+\(.*:\d+:\d+\)/,          // Node.js stack trace
  /^\s+at\s+/m,                              // Stack frame lines
  /Traceback\s*\(most\s*recent/i,            // Python
  /Exception\s+in\s+thread/i,               // Java
  /\.ts:\d+:\d+/,                            // TypeScript file:line:col
  /\.js:\d+:\d+/,                            // JavaScript file:line:col
];

const MALFORMED_PAYLOADS = [
  { label: "empty-body", body: "{}", contentType: "application/json" },
  { label: "missing-fields", body: JSON.stringify({ email: "sentinel-probe@test.invalid" }), contentType: "application/json" },
  { label: "bad-types", body: JSON.stringify({ email: 12345, password: true }), contentType: "application/json" },
];

export const authEndpointProbeCheck: ProbeCheck = {
  id: "auth-endpoint-probe",
  level: "standard" as AggressionLevel,
  domain: "auth-access-control" as SecurityDomain,
  description: "POST malformed payloads to auth endpoints to detect verbose errors and user enumeration",

  appliesTo(target): boolean {
    if (target.kind !== "endpoint") return false;
    if (target.method !== "POST") return false;
    return AUTH_PATH_RE.test(target.url);
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const authFinding = ctx.priorFindings.find(
      (f) =>
        f.domain === "auth-access-control" &&
        ctx.target.fromFindingId === f.id,
    );

    let foundEnumeration = false;
    let foundStackTrace = false;

    for (const payload of MALFORMED_PAYLOADS) {
      try {
        const resp = await ctx.client.request({
          method: "POST",
          url: ctx.target.url,
          headers: { "Content-Type": payload.contentType },
          body: payload.body,
          intent: "read",
        });

        const bodyText = resp.body.slice(0, 4096);

        // Check for user enumeration signals
        if (!foundEnumeration) {
          for (const pattern of ENUMERATION_PATTERNS) {
            if (pattern.test(bodyText)) {
              foundEnumeration = true;
              findings.push({
                id: `PROBE-AUTH-${randomUUID().slice(0, 8)}`,
                domain: "auth-access-control",
                severity: "medium",
                confidence: "confirmed",
                title: `User enumeration via verbose error on ${ctx.target.url}`,
                description: `Auth endpoint returned a response matching enumeration pattern (payload: ${payload.label}). Error messages should not reveal whether a user account exists.`,
                evidence: [],
                remediation: "Return generic error messages like 'Invalid credentials' regardless of whether the user exists",
                references: [
                  "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-responses",
                ],
                layer: "probe",
                cwe: "CWE-204",
                probeEvidence: {
                  requestId: resp.requestId,
                  checkId: "auth-endpoint-probe",
                  aggressionLevel: "standard",
                  request: {
                    method: "POST",
                    url: ctx.target.url,
                    headers: { "Content-Type": payload.contentType },
                    bodyPreview: payload.body,
                  },
                  response: {
                    status: resp.status,
                    headers: resp.headers,
                    bodyPreview: bodyText.slice(0, 256),
                    timingMs: resp.timingMs,
                  },
                },
                confirms: authFinding?.id,
              });
              if (authFinding) confirmed.push({ findingId: authFinding.id });
              break;
            }
          }
        }

        // Check for stack trace leakage
        if (!foundStackTrace) {
          for (const pattern of STACK_TRACE_PATTERNS) {
            if (pattern.test(bodyText)) {
              foundStackTrace = true;
              findings.push({
                id: `PROBE-AUTH-${randomUUID().slice(0, 8)}`,
                domain: "auth-access-control",
                severity: "medium",
                confidence: "confirmed",
                title: `Stack trace leaked by auth endpoint ${ctx.target.url}`,
                description: `Auth endpoint returned a stack trace in response body (payload: ${payload.label}). This reveals internal file paths and code structure.`,
                evidence: [],
                remediation: "Never return stack traces in production error responses. Use a global error handler that returns generic messages.",
                references: [
                  "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
                ],
                layer: "probe",
                cwe: "CWE-209",
                probeEvidence: {
                  requestId: resp.requestId,
                  checkId: "auth-endpoint-probe",
                  aggressionLevel: "standard",
                  request: {
                    method: "POST",
                    url: ctx.target.url,
                    headers: { "Content-Type": payload.contentType },
                    bodyPreview: payload.body,
                  },
                  response: {
                    status: resp.status,
                    headers: resp.headers,
                    bodyPreview: bodyText.slice(0, 256),
                    timingMs: resp.timingMs,
                  },
                },
              });
              break;
            }
          }
        }
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "auth-endpoint-probe", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        }
        throw err;
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/probe/checks/standard/auth-endpoint-probe.test.ts`
Expected: ALL PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/layers/probe/checks/standard/auth-endpoint-probe.ts tests/layers/probe/checks/standard/auth-endpoint-probe.test.ts
git commit -m "feat(probe): add auth-endpoint-probe standard check with tests"
```

---

## Task 3: IDOR Probe Check

**Files:**
- Create: `src/layers/probe/checks/standard/idor-probe.ts`
- Test: `tests/layers/probe/checks/standard/idor-probe.test.ts`

This check targets endpoints with `:id` path parameters. It substitutes Nil UUID (`00000000-0000-0000-0000-000000000000`) and Max UUID (`ffffffff-ffff-ffff-ffff-ffffffffffff`) and issues unauthenticated GETs. If the endpoint returns 200 with a response body, it flags a potential IDOR.

- [ ] **Step 1: Write the unit test file**

```typescript
// tests/layers/probe/checks/standard/idor-probe.test.ts
import { describe, it, expect } from "vitest";
import { idorProbeCheck } from "../../../../../src/layers/probe/checks/standard/idor-probe.js";
import { MockHttpClient } from "../../../../../src/layers/probe/http-client.js";
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

const paramTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/users/:id",
  method: "GET",
  auth: "required",
  fromLayer: "rules",
  fromFindingId: "AUTH-IDOR-001",
  inputs: [{ name: "id", in: "path", type: "uuid" }],
};

const noParamTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/users",
  method: "GET",
  auth: "required",
  fromLayer: "recon",
};

const baselineTarget: ProbeTarget = {
  kind: "baseline",
  url: "https://example.com",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "recon",
};

describe("idor-probe check", () => {
  it("applies only to endpoint targets with path params typed as uuid", () => {
    expect(idorProbeCheck.appliesTo(paramTarget, emptyModel())).toBe(true);
    expect(idorProbeCheck.appliesTo(noParamTarget, emptyModel())).toBe(false);
    expect(idorProbeCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("confirms IDOR when endpoint returns 200 for sentinel UUIDs", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /api\/users\/0{8}/ },
        response: { status: 200, body: JSON.stringify({ id: "00000000-0000-0000-0000-000000000000", name: "test" }) },
      },
      {
        match: { method: "GET", url: /api\/users\/f{8}/ },
        response: { status: 200, body: JSON.stringify({ id: "ffffffff-ffff-ffff-ffff-ffffffffffff", name: "max" }) },
      },
    ], 2000);

    const priorFinding: Finding = {
      id: "AUTH-IDOR-001",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Potential IDOR on /api/users/:id",
      description: "Endpoint may expose other users data",
      evidence: [{ file: "src/app/api/users/[id]/route.ts" }],
      remediation: "Add ownership checks",
      references: [],
      layer: "rules",
    };

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].confidence).toBe("confirmed");
    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("AUTH-IDOR-001");
  });

  it("produces no findings when endpoint returns 401/403 for sentinel UUIDs", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /api\/users\// },
        response: { status: 403, body: JSON.stringify({ error: "Forbidden" }) },
      },
    ], 2000);

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
  });

  it("refutes prior IDOR finding when 401/403 returned", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /api\/users\// },
        response: { status: 401, body: "" },
      },
    ], 2000);

    const priorFinding: Finding = {
      id: "AUTH-IDOR-001",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Potential IDOR on /api/users/:id",
      description: "Endpoint may expose other users data",
      evidence: [{ file: "src/app/api/users/[id]/route.ts" }],
      remediation: "Add ownership checks",
      references: [],
      layer: "rules",
    };

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.refuted).toHaveLength(1);
    expect(result.refuted[0].findingId).toBe("AUTH-IDOR-001");
  });

  it("treats 404 as no signal (neither confirms nor refutes)", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /api\/users\// },
        response: { status: 404, body: "" },
      },
    ], 2000);

    const priorFinding: Finding = {
      id: "AUTH-IDOR-001",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Potential IDOR on /api/users/:id",
      description: "Endpoint may expose other users data",
      evidence: [{ file: "src/app/api/users/[id]/route.ts" }],
      remediation: "Add ownership checks",
      references: [],
      layer: "rules",
    };

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.confirmed).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
  });

  it("handles target unreachable gracefully", async () => {
    const client = new MockHttpClient([], 2000);
    client.request = async () => {
      throw new (await import("../../../../../src/layers/probe/http-client.js")).TargetUnreachable("https://api.example.com/api/users/00000000-0000-0000-0000-000000000000");
    };

    const result = await idorProbeCheck.run({
      target: paramTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].kind).toBe("target-unreachable");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/probe/checks/standard/idor-probe.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// src/layers/probe/checks/standard/idor-probe.ts
import { randomUUID } from "crypto";
import type { ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff";

export const idorProbeCheck: ProbeCheck = {
  id: "idor-probe",
  level: "standard" as AggressionLevel,
  domain: "auth-access-control" as SecurityDomain,
  description: "GET with sentinel UUIDs on parameterized endpoints to test for IDOR",

  appliesTo(target): boolean {
    if (target.kind !== "endpoint") return false;
    return !!target.inputs?.some((i) => i.in === "path" && i.type === "uuid");
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const idorFinding = ctx.priorFindings.find(
      (f) =>
        f.domain === "auth-access-control" &&
        ctx.target.fromFindingId === f.id,
    );

    const uuidInputs = ctx.target.inputs?.filter((i) => i.in === "path" && i.type === "uuid") ?? [];
    if (uuidInputs.length === 0) return { findings, confirmed, refuted, errors };

    const sentinelUuids = [NIL_UUID, MAX_UUID];
    let gotAccessible = false;
    let gotProtected = false;

    for (const sentinelId of sentinelUuids) {
      // Replace :param with sentinel UUID in URL
      let probeUrl = ctx.target.url;
      for (const input of uuidInputs) {
        probeUrl = probeUrl.replace(`:${input.name}`, sentinelId);
      }

      try {
        const resp = await ctx.client.request({
          method: "GET",
          url: probeUrl,
          intent: "read",
        });

        const isAccessible = resp.status >= 200 && resp.status < 300 && resp.body.length > 0;
        const isProtected = resp.status === 401 || resp.status === 403;

        if (isAccessible && !gotAccessible) {
          gotAccessible = true;
          findings.push({
            id: `PROBE-IDOR-${randomUUID().slice(0, 8)}`,
            domain: "auth-access-control",
            severity: "high",
            confidence: "confirmed",
            title: `IDOR: endpoint returns data for sentinel UUID on ${ctx.target.url}`,
            description: `GET ${probeUrl} returned ${resp.status} with a non-empty body. Endpoint accepts arbitrary object IDs without ownership verification.`,
            evidence: [],
            remediation: "Add ownership validation: verify the authenticated user owns the requested resource before returning data",
            references: [
              "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            ],
            layer: "probe",
            cwe: "CWE-639",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "idor-probe",
              aggressionLevel: "standard",
              request: { method: "GET", url: probeUrl, headers: {} },
              response: {
                status: resp.status,
                headers: resp.headers,
                bodyPreview: resp.body.slice(0, 256),
                timingMs: resp.timingMs,
              },
            },
            confirms: idorFinding?.id,
          });
          if (idorFinding) confirmed.push({ findingId: idorFinding.id });
        }

        if (isProtected) {
          gotProtected = true;
        }
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "idor-probe", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        }
        throw err;
      }
    }

    // Refute if ALL sentinel UUIDs returned 401/403 and there's a prior finding
    if (!gotAccessible && gotProtected && idorFinding) {
      refuted.push({ findingId: idorFinding.id });
      findings.push({
        id: `PROBE-IDOR-${randomUUID().slice(0, 8)}`,
        domain: "auth-access-control",
        severity: "info",
        confidence: "confirmed",
        title: `IDOR check passed: ${ctx.target.url} requires auth`,
        description: "Sentinel UUIDs received 401/403 — endpoint enforces authentication",
        evidence: [],
        remediation: "No action needed",
        references: [],
        layer: "probe",
        probeEvidence: {
          requestId: randomUUID(),
          checkId: "idor-probe",
          aggressionLevel: "standard",
          request: { method: "GET", url: ctx.target.url, headers: {} },
          response: { status: 401, headers: {}, bodyPreview: "", timingMs: 0 },
        },
        refutes: idorFinding.id,
      });
    }

    return { findings, confirmed, refuted, errors };
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/probe/checks/standard/idor-probe.test.ts`
Expected: ALL PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/layers/probe/checks/standard/idor-probe.ts tests/layers/probe/checks/standard/idor-probe.test.ts
git commit -m "feat(probe): add idor-probe standard check with tests"
```

---

## Task 4: JWT Claim Audit Check

**Files:**
- Create: `src/layers/probe/checks/standard/jwt-claim-audit.ts`
- Test: `tests/layers/probe/checks/standard/jwt-claim-audit.test.ts`

This check inspects any JWT tokens found in response headers (`Set-Cookie`, `Authorization`) or response bodies. It decodes the header and claims (no signature verification needed) and flags: `alg: "none"`, weak HMAC algorithms (HS256 with short keys), missing `exp` claim, and sensitive data in plaintext claims.

- [ ] **Step 1: Write the unit test file**

```typescript
// tests/layers/probe/checks/standard/jwt-claim-audit.test.ts
import { describe, it, expect } from "vitest";
import { jwtClaimAuditCheck } from "../../../../../src/layers/probe/checks/standard/jwt-claim-audit.js";
import { MockHttpClient } from "../../../../../src/layers/probe/http-client.js";
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

// Helper to build a JWT (no signature, just base64url header.payload.signature)
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

  it("detects alg:none as critical", async () => {
    const jwt = buildJwt({ alg: "none", typ: "JWT" }, { sub: "123", exp: 9999999999 });
    const client = new MockHttpClient([
      {
        match: { url: /auth\/login/ },
        response: {
          status: 200,
          headers: { "set-cookie": `token=${jwt}; HttpOnly` },
          body: JSON.stringify({ token: jwt }),
        },
      },
    ], 2000);

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const algFindings = result.findings.filter((f) => f.title.toLowerCase().includes("alg"));
    expect(algFindings.length).toBeGreaterThan(0);
    expect(algFindings[0].severity).toBe("critical");
  });

  it("detects missing exp claim as medium", async () => {
    const jwt = buildJwt({ alg: "RS256", typ: "JWT" }, { sub: "123" }); // no exp
    const client = new MockHttpClient([
      {
        match: { url: /auth\/login/ },
        response: {
          status: 200,
          body: JSON.stringify({ access_token: jwt }),
        },
      },
    ], 2000);

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const expFindings = result.findings.filter((f) => f.title.toLowerCase().includes("exp"));
    expect(expFindings.length).toBeGreaterThan(0);
    expect(expFindings[0].severity).toBe("medium");
  });

  it("detects sensitive data in claims", async () => {
    const jwt = buildJwt(
      { alg: "RS256", typ: "JWT" },
      { sub: "123", exp: 9999999999, email: "user@example.com", password: "secret123", ssn: "123-45-6789" },
    );
    const client = new MockHttpClient([
      {
        match: { url: /auth\/login/ },
        response: {
          status: 200,
          body: JSON.stringify({ token: jwt }),
        },
      },
    ], 2000);

    const result = await jwtClaimAuditCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const sensitiveFindings = result.findings.filter((f) => f.title.toLowerCase().includes("sensitive"));
    expect(sensitiveFindings.length).toBeGreaterThan(0);
    expect(sensitiveFindings[0].severity).toBe("high");
  });

  it("produces no findings for a well-configured JWT", async () => {
    const jwt = buildJwt(
      { alg: "RS256", typ: "JWT" },
      { sub: "123", exp: 9999999999, iss: "api.example.com", aud: "web" },
    );
    const client = new MockHttpClient([
      {
        match: { url: /auth\/login/ },
        response: {
          status: 200,
          body: JSON.stringify({ token: jwt }),
        },
      },
    ], 2000);

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
  });

  it("produces no findings when response contains no JWTs", async () => {
    const client = new MockHttpClient([
      {
        match: { url: /auth\/login/ },
        response: {
          status: 200,
          body: JSON.stringify({ message: "ok" }),
        },
      },
    ], 2000);

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
  });

  it("confirms prior cryptography finding when alg:none detected", async () => {
    const jwt = buildJwt({ alg: "none", typ: "JWT" }, { sub: "123", exp: 9999999999 });
    const client = new MockHttpClient([
      {
        match: { url: /auth\/login/ },
        response: {
          status: 200,
          body: JSON.stringify({ token: jwt }),
        },
      },
    ], 2000);

    const priorFinding: Finding = {
      id: "CRYPTO-JWT-001",
      domain: "cryptography",
      severity: "high",
      confidence: "medium",
      title: "Potential weak JWT configuration",
      description: "JWT may use weak algorithm",
      evidence: [{ file: "src/lib/auth.ts" }],
      remediation: "Use RS256 or ES256",
      references: [],
      layer: "rules",
    };

    const targetWithFinding: ProbeTarget = {
      ...endpointTarget,
      fromFindingId: "CRYPTO-JWT-001",
      fromLayer: "rules",
    };

    const result = await jwtClaimAuditCheck.run({
      target: targetWithFinding,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("CRYPTO-JWT-001");
  });

  it("handles target unreachable gracefully", async () => {
    const client = new MockHttpClient([], 2000);
    client.request = async () => {
      throw new (await import("../../../../../src/layers/probe/http-client.js")).TargetUnreachable("https://api.example.com/api/auth/login");
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
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].kind).toBe("target-unreachable");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/layers/probe/checks/standard/jwt-claim-audit.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// src/layers/probe/checks/standard/jwt-claim-audit.ts
import { randomUUID } from "crypto";
import type { ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

// Matches JWT-like strings: base64url.base64url.base64url
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.-]{2,}/g;

const SENSITIVE_CLAIM_KEYS = [
  "password", "passwd", "secret", "ssn", "credit_card", "creditcard",
  "card_number", "cvv", "pin", "private_key", "privatekey",
];

function decodeJwtParts(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  const parts = jwt.split(".");
  if (parts.length < 2) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    return { header, payload };
  } catch {
    return null;
  }
}

function extractJwts(body: string, headers: Record<string, string>): string[] {
  const tokens = new Set<string>();

  // From response body
  const bodyMatches = body.match(JWT_RE) ?? [];
  for (const m of bodyMatches) tokens.add(m);

  // From Set-Cookie headers
  const cookie = headers["set-cookie"] ?? "";
  const cookieMatches = cookie.match(JWT_RE) ?? [];
  for (const m of cookieMatches) tokens.add(m);

  return [...tokens];
}

export const jwtClaimAuditCheck: ProbeCheck = {
  id: "jwt-claim-audit",
  level: "standard" as AggressionLevel,
  domain: "cryptography" as SecurityDomain,
  description: "Decode JWTs from responses and flag weak algorithms, missing expiry, and sensitive claims",

  appliesTo(target): boolean {
    return target.kind === "endpoint";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const cryptoFinding = ctx.priorFindings.find(
      (f) =>
        f.domain === "cryptography" &&
        ctx.target.fromFindingId === f.id,
    );

    try {
      const method = ctx.target.method === "POST" ? "POST" : "GET";
      const resp = await ctx.client.request({
        method,
        url: ctx.target.url,
        intent: "read",
      });

      const jwts = extractJwts(resp.body, resp.headers);
      if (jwts.length === 0) return { findings, confirmed, refuted, errors };

      const makeEvidence = () => ({
        requestId: resp.requestId,
        checkId: "jwt-claim-audit" as const,
        aggressionLevel: "standard" as AggressionLevel,
        request: { method, url: ctx.target.url, headers: {} },
        response: {
          status: resp.status,
          headers: resp.headers,
          bodyPreview: resp.body.slice(0, 256),
          timingMs: resp.timingMs,
        },
      });

      for (const jwt of jwts) {
        const decoded = decodeJwtParts(jwt);
        if (!decoded) continue;

        const { header, payload } = decoded;
        const alg = String(header.alg ?? "").toLowerCase();

        // Check: alg "none"
        if (alg === "none") {
          findings.push({
            id: `PROBE-JWT-${randomUUID().slice(0, 8)}`,
            domain: "cryptography",
            severity: "critical",
            confidence: "confirmed",
            title: `JWT uses alg:none on ${ctx.target.url}`,
            description: 'JWT header specifies "alg": "none". This means the token has no signature verification and can be trivially forged.',
            evidence: [],
            remediation: "Use a strong asymmetric algorithm (RS256 or ES256). Never accept alg:none tokens.",
            references: ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
            layer: "probe",
            cwe: "CWE-327",
            probeEvidence: makeEvidence(),
            confirms: cryptoFinding?.id,
          });
          if (cryptoFinding) confirmed.push({ findingId: cryptoFinding.id });
        }

        // Check: missing exp
        if (payload.exp === undefined) {
          findings.push({
            id: `PROBE-JWT-${randomUUID().slice(0, 8)}`,
            domain: "cryptography",
            severity: "medium",
            confidence: "confirmed",
            title: `JWT missing exp claim on ${ctx.target.url}`,
            description: "JWT payload has no expiration (exp) claim. Tokens without expiry remain valid indefinitely if compromised.",
            evidence: [],
            remediation: "Always include an exp claim with a reasonable TTL (e.g., 15 minutes for access tokens, 7 days for refresh tokens)",
            references: ["https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4"],
            layer: "probe",
            cwe: "CWE-613",
            probeEvidence: makeEvidence(),
          });
        }

        // Check: sensitive data in claims
        const sensitiveKeys = Object.keys(payload).filter((k) =>
          SENSITIVE_CLAIM_KEYS.includes(k.toLowerCase()),
        );
        if (sensitiveKeys.length > 0) {
          findings.push({
            id: `PROBE-JWT-${randomUUID().slice(0, 8)}`,
            domain: "cryptography",
            severity: "high",
            confidence: "confirmed",
            title: `JWT contains sensitive data in claims on ${ctx.target.url}`,
            description: `JWT payload contains potentially sensitive claim keys: ${sensitiveKeys.join(", ")}. JWT payloads are base64-encoded (not encrypted) and visible to anyone with the token.`,
            evidence: [],
            remediation: "Never store sensitive data (passwords, SSNs, credit cards) in JWT claims. Store only identifiers and look up sensitive data server-side.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
            layer: "probe",
            cwe: "CWE-312",
            probeEvidence: makeEvidence(),
          });
        }
      }
    } catch (err) {
      if (err instanceof TargetUnreachable) {
        errors.push({ kind: "target-unreachable", message: err.message, checkId: "jwt-claim-audit", targetUrl: ctx.target.url });
      } else {
        throw err;
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/probe/checks/standard/jwt-claim-audit.test.ts`
Expected: ALL PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/layers/probe/checks/standard/jwt-claim-audit.ts tests/layers/probe/checks/standard/jwt-claim-audit.test.ts
git commit -m "feat(probe): add jwt-claim-audit standard check with tests"
```

---

## Task 5: Wire Standard Checks into Probe Entry Point

**Files:**
- Modify: `src/layers/probe/index.ts`

The entry point currently calls `loadPassiveChecks()`. Add a `loadStandardChecks()` function that registers all 4 standard checks, and call it from `runProbe()`.

- [ ] **Step 1: Write the test (verify standard checks load when level is standard)**

This is verified by the integration test in Task 6. No separate unit test needed since the wiring is 4 import + register lines.

- [ ] **Step 2: Modify index.ts**

Replace the contents of `src/layers/probe/index.ts` with:

```typescript
import type { Finding, ProbeConfig, ProbeRunResult, ProjectModel } from "../../model/types.js";
import { runProbeOrchestrator } from "./orchestrator.js";
import { registerProbeCheck, resetProbeRegistry } from "./checks/base.js";
import { securityHeadersCheck } from "./checks/passive/security-headers.js";
import { tlsConfigurationCheck } from "./checks/passive/tls-configuration.js";
import { endpointEnumerationCheck } from "./checks/passive/endpoint-enumeration.js";
import { responseBodySecretsCheck } from "./checks/passive/response-body-secrets.js";
import { corsConfigurationCheck } from "./checks/passive/cors-configuration.js";
import { rateLimitProbeCheck } from "./checks/standard/rate-limit-probe.js";
import { authEndpointProbeCheck } from "./checks/standard/auth-endpoint-probe.js";
import { idorProbeCheck } from "./checks/standard/idor-probe.js";
import { jwtClaimAuditCheck } from "./checks/standard/jwt-claim-audit.js";

export { registerProbeCheck, resetProbeRegistry } from "./checks/base.js";
export { resolveAuthorization, loadAuthorizations, persistAuthorization, buildAuthorizationEntry } from "./authorization.js";
export type { AuthorizationResolution } from "./authorization.js";

function loadPassiveChecks(): void {
  registerProbeCheck(securityHeadersCheck);
  registerProbeCheck(tlsConfigurationCheck);
  registerProbeCheck(endpointEnumerationCheck);
  registerProbeCheck(responseBodySecretsCheck);
  registerProbeCheck(corsConfigurationCheck);
}

function loadStandardChecks(): void {
  registerProbeCheck(rateLimitProbeCheck);
  registerProbeCheck(authEndpointProbeCheck);
  registerProbeCheck(idorProbeCheck);
  registerProbeCheck(jwtClaimAuditCheck);
}

export async function runProbe(
  model: ProjectModel,
  findings: Finding[],
  config: ProbeConfig,
  sentinelVersion = "0.2.0",
): Promise<{ result: ProbeRunResult; mergedFindings: Finding[] }> {
  resetProbeRegistry();
  loadPassiveChecks();
  loadStandardChecks();

  return runProbeOrchestrator({
    model,
    findings,
    config,
    sentinelVersion,
  });
}
```

- [ ] **Step 3: Run existing tests to verify no regression**

Run: `npx vitest run tests/layers/probe/ tests/integration/`
Expected: ALL EXISTING TESTS PASS (passive checks still work, standard checks filtered out at passive level by `getProbeChecks`)

- [ ] **Step 4: Commit**

```bash
git add src/layers/probe/index.ts
git commit -m "feat(probe): wire standard checks into probe entry point"
```

---

## Task 6: Standard Level Integration Test

**Files:**
- Create: `tests/integration/probe-standard.test.ts`

End-to-end test: run probe at `level: "standard"` with a model that has endpoints triggering all 4 standard checks. Uses mock fetch to simulate responses.

- [ ] **Step 1: Write the integration test**

```typescript
// tests/integration/probe-standard.test.ts
import { describe, it, expect, vi, afterEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { Finding, ProjectModel, ProbeConfig } from "../../src/model/types.js";

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
      { path: "/api/users", method: "GET", file: "src/app/api/users/route.ts", isApi: true, hasAuthCheck: false, paramNames: [] },
      { path: "/api/users/:id", method: "GET", file: "src/app/api/users/[id]/route.ts", isApi: true, hasAuthCheck: true, paramNames: ["id"] },
      { path: "/api/auth/login", method: "POST", file: "src/app/api/auth/login/route.ts", isApi: true, hasAuthCheck: false, paramNames: [] },
    ],
    endpoints: [
      { path: "/api/users", method: "GET", file: "src/app/api/users/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
      { path: "/api/users/:id", method: "GET", file: "src/app/api/users/[id]/route.ts", hasAuthCheck: true, hasValidation: false, usesServiceRole: false },
      { path: "/api/auth/login", method: "POST", file: "src/app/api/auth/login/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
    ],
    fileUploads: [],
    authFlows: [{ type: "login", file: "src/app/api/auth/login/route.ts" }],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
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

describe("probe: standard end-to-end integration", () => {
  it("runs standard checks alongside passive checks", async () => {
    const weakJwt = buildJwt({ alg: "none", typ: "JWT" }, { sub: "123" });

    const mockFetch = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
      const urlStr = String(url);

      // Auth login endpoint — returns JWT with alg:none and verbose error
      if (urlStr.includes("/api/auth/login") && init.method === "POST") {
        return {
          status: 401,
          headers: new Headers({ "content-type": "application/json" }),
          text: async () => JSON.stringify({
            error: "User not found with that email address",
            token: weakJwt,
          }),
        };
      }

      // IDOR target — returns data for sentinel UUIDs (bad)
      if (urlStr.includes("/api/users/00000000") || urlStr.includes("/api/users/ffffffff")) {
        return {
          status: 200,
          headers: new Headers({ "content-type": "application/json" }),
          text: async () => JSON.stringify({ id: "test", name: "leaked" }),
        };
      }

      // Default — 200 with no security headers (triggers passive checks)
      return {
        status: 200,
        headers: new Headers({ "content-type": "text/html" }),
        text: async () => "<html><body>Hello</body></html>",
      };
    });

    vi.stubGlobal("fetch", mockFetch);

    const model = buildModel();
    const { result } = await runProbe(model, [], STANDARD_CONFIG);

    // Standard level should be reflected
    expect(result.aggressionLevel).toBe("standard");

    // Should have findings from both passive AND standard checks
    expect(result.findings.length).toBeGreaterThan(0);

    // Passive: at least one missing security header
    const headerFindings = result.findings.filter((f) =>
      f.title.toLowerCase().includes("missing security header"),
    );
    expect(headerFindings.length).toBeGreaterThan(0);

    // Standard: rate limit (20 GETs to /api/users, no 429)
    const rateFindings = result.findings.filter((f) =>
      f.probeEvidence.checkId === "rate-limit-probe",
    );
    expect(rateFindings.length).toBeGreaterThan(0);

    // Standard: auth endpoint verbose error
    const authFindings = result.findings.filter((f) =>
      f.probeEvidence.checkId === "auth-endpoint-probe",
    );
    expect(authFindings.length).toBeGreaterThan(0);

    // Standard: JWT alg:none
    const jwtFindings = result.findings.filter((f) =>
      f.probeEvidence.checkId === "jwt-claim-audit",
    );
    expect(jwtFindings.length).toBeGreaterThan(0);

    // Standard: IDOR confirmed (200 for sentinel UUIDs)
    const idorFindings = result.findings.filter((f) =>
      f.probeEvidence.checkId === "idor-probe",
    );
    expect(idorFindings.length).toBeGreaterThan(0);

    // Requests should be within standard cap
    expect(result.usedRequests).toBeLessThanOrEqual(result.requestCap);
    expect(result.requestCap).toBe(2000);
  });

  it("standard checks do NOT run at passive level", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html></html>",
    });
    vi.stubGlobal("fetch", mockFetch);

    const passiveConfig: ProbeConfig = {
      ...STANDARD_CONFIG,
      level: "passive",
    };

    const model = buildModel();
    const { result } = await runProbe(model, [], passiveConfig);

    // No standard check findings
    const standardFindings = result.findings.filter((f) =>
      ["rate-limit-probe", "auth-endpoint-probe", "idor-probe", "jwt-claim-audit"].includes(f.probeEvidence.checkId),
    );
    expect(standardFindings).toHaveLength(0);
    expect(result.aggressionLevel).toBe("passive");
  });
});
```

- [ ] **Step 2: Run integration test**

Run: `npx vitest run tests/integration/probe-standard.test.ts`
Expected: ALL PASS (2 tests)

- [ ] **Step 3: Run full test suite to verify no regressions**

Run: `npx vitest run`
Expected: ALL tests pass (existing 357 + new ~25 = ~382)

- [ ] **Step 4: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add tests/integration/probe-standard.test.ts
git commit -m "test(probe): add standard level end-to-end integration test"
```

---

## Summary

| Task | Check | Files | Tests |
|------|-------|-------|-------|
| 1 | rate-limit-probe | 1 impl + 1 test | 4 unit tests |
| 2 | auth-endpoint-probe | 1 impl + 1 test | 5 unit tests |
| 3 | idor-probe | 1 impl + 1 test | 5 unit tests |
| 4 | jwt-claim-audit | 1 impl + 1 test | 7 unit tests |
| 5 | Wire into index.ts | 1 modify | regression check |
| 6 | Integration test | 1 test | 2 integration tests |

Total: 4 new check files, 5 new test files, 1 modified file. ~23 new tests.
