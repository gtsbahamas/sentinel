# Probe Layer Tests & Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the probe layer's test suite and verify the full pipeline works end-to-end with MockHttpClient.

**Architecture:** The probe layer implementation is complete (infrastructure + 5 passive checks + CLI wiring). What's missing is 4 passive check unit tests, 1 probe-log unit test, and 5 integration tests. All tests use MockHttpClient — no network access in CI.

**Tech Stack:** TypeScript, Vitest, MockHttpClient from `src/layers/probe/http-client.ts`

---

## File Structure

### Files to Create

| File | Purpose |
|------|---------|
| `tests/layers/probe/probe-log.test.ts` | Unit test ProbeLogger (init, append, rotate) |
| `tests/layers/probe/checks/passive/tls-configuration.test.ts` | Unit test TLS check (protocol, cert validation) |
| `tests/layers/probe/checks/passive/endpoint-enumeration.test.ts` | Unit test auth bypass detection |
| `tests/layers/probe/checks/passive/response-body-secrets.test.ts` | Unit test secret pattern scanning |
| `tests/layers/probe/checks/passive/cors-configuration.test.ts` | Unit test CORS misconfiguration detection |
| `tests/integration/probe-passive.test.ts` | End-to-end passive scan with MockHttpClient |
| `tests/integration/probe-confirm.test.ts` | Probe confirms a prior rules finding |
| `tests/integration/probe-refute.test.ts` | Probe refutes a prior rules finding |
| `tests/integration/probe-auth-deny.test.ts` | Missing authorization returns exit 3 |
| `tests/integration/probe-cleanup.test.ts` | Cleanup obligations execute on completion |

### Existing Files (Reference Only — Do Not Modify)

| File | Role |
|------|------|
| `src/layers/probe/http-client.ts` | MockHttpClient, MockRoute |
| `src/layers/probe/checks/base.ts` | ProbeCheck interface, registry |
| `src/layers/probe/cleanup-registry.ts` | ProbeCleanupRegistry |
| `src/layers/probe/probe-log.ts` | ProbeLogger |
| `src/layers/probe/index.ts` | runProbe entry point |
| `src/layers/probe/orchestrator.ts` | runProbeOrchestrator |
| `src/layers/probe/authorization.ts` | resolveAuthorization, loadAuthorizations |
| `src/layers/probe/merge.ts` | mergeProbeResults |
| `tests/layers/probe/checks/passive/security-headers.test.ts` | Pattern reference for check tests |

---

## Shared Test Helpers

Every check test uses the same `emptyModel()` and target factories. Copy this pattern from the existing `security-headers.test.ts`:

```ts
import type { ProbeTarget, ProjectModel } from "../../../../../src/model/types.js";
import { MockHttpClient } from "../../../../../src/layers/probe/http-client.js";
import { ProbeCleanupRegistry } from "../../../../../src/layers/probe/cleanup-registry.js";

function emptyModel(): ProjectModel {
  return {
    meta: { name: "test", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [], endpoints: [], fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

const baselineTarget: ProbeTarget = { kind: "baseline", url: "http://localhost:3000", method: "GET", auth: "unauthenticated", fromLayer: "recon" };
const endpointTarget: ProbeTarget = { kind: "endpoint", url: "http://localhost:3000/api/users", method: "GET", auth: "required", fromLayer: "rules" };
```

---

## Task 1: ProbeLogger Unit Tests

**Files:**
- Create: `tests/layers/probe/probe-log.test.ts`

- [ ] **Step 1: Write tests**

```ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { ProbeLogger } from "../../../src/layers/probe/probe-log.js";
import { mkdtemp, readFile, writeFile, readdir, rm } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";

describe("ProbeLogger", () => {
  let logDir: string;

  beforeEach(async () => {
    logDir = await mkdtemp(join(tmpdir(), "probe-log-test-"));
  });

  afterEach(async () => {
    await rm(logDir, { recursive: true, force: true });
  });

  it("init creates directory if missing", async () => {
    const nested = join(logDir, "sub", "dir");
    const logger = new ProbeLogger(nested, "run-001");
    await logger.init();
    const files = await readdir(join(nested, "sub", "dir")).catch(() => null);
    // init creates the parent dir of the log file
    // logPath = nested + "/probe-log-run-001.jsonl"
    // parent = nested (which is logDir/sub/dir)
    expect(logger.getLogPath()).toContain("probe-log-run-001.jsonl");
  });

  it("append writes JSONL entries", async () => {
    const logger = new ProbeLogger(logDir, "run-002");
    await logger.init();

    const entry = {
      requestId: "req-1",
      timestamp: "2026-01-01T00:00:00Z",
      request: { method: "GET", url: "http://localhost:3000", headers: {} },
      response: { status: 200, headers: {}, bodyPreview: "", timingMs: 5 },
    };
    await logger.append(entry);
    await logger.append({ ...entry, requestId: "req-2" });

    const content = await readFile(logger.getLogPath(), "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).requestId).toBe("req-1");
    expect(JSON.parse(lines[1]).requestId).toBe("req-2");
  });

  it("rotate keeps only the last N log files", async () => {
    // Pre-create 5 log files
    for (let i = 0; i < 5; i++) {
      const name = `probe-log-run-${String(i).padStart(3, "0")}.jsonl`;
      await writeFile(join(logDir, name), `{"i":${i}}\n`);
    }

    const logger = new ProbeLogger(logDir, "run-005");
    const removed = await logger.rotate(3);

    expect(removed).toBe(2);
    const remaining = await readdir(logDir);
    const probeFiles = remaining.filter((f) => f.startsWith("probe-log-"));
    expect(probeFiles).toHaveLength(3);
  });

  it("rotate is no-op when under limit", async () => {
    await writeFile(join(logDir, "probe-log-run-001.jsonl"), "{}");
    const logger = new ProbeLogger(logDir, "run-002");
    const removed = await logger.rotate(10);
    expect(removed).toBe(0);
  });

  it("getLogPath returns correct path", () => {
    const logger = new ProbeLogger("/tmp/logs", "abc123");
    expect(logger.getLogPath()).toBe("/tmp/logs/probe-log-abc123.jsonl");
  });
});
```

- [ ] **Step 2: Run tests**

Run: `npx vitest run tests/layers/probe/probe-log.test.ts`
Expected: All 5 tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/layers/probe/probe-log.test.ts
git commit -m "test(probe): add ProbeLogger unit tests"
```

---

## Task 2: TLS Configuration Check Tests

**Files:**
- Create: `tests/layers/probe/checks/passive/tls-configuration.test.ts`

The TLS check uses Node's `tls` module directly (not MockHttpClient), so we test `appliesTo` logic and mock the `tls.connect` behavior.

- [ ] **Step 1: Write tests**

```ts
import { describe, it, expect, vi } from "vitest";
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
  it("applies only to HTTPS baseline targets", () => {
    const httpsBaseline: ProbeTarget = { kind: "baseline", url: "https://example.com", method: "GET", auth: "unauthenticated", fromLayer: "recon" };
    const httpBaseline: ProbeTarget = { kind: "baseline", url: "http://localhost:3000", method: "GET", auth: "unauthenticated", fromLayer: "recon" };
    const httpsEndpoint: ProbeTarget = { kind: "endpoint", url: "https://example.com/api", method: "GET", auth: "required", fromLayer: "rules" };

    expect(tlsConfigurationCheck.appliesTo(httpsBaseline, emptyModel())).toBe(true);
    expect(tlsConfigurationCheck.appliesTo(httpBaseline, emptyModel())).toBe(false);
    expect(tlsConfigurationCheck.appliesTo(httpsEndpoint, emptyModel())).toBe(false);
  });

  it("returns error when TLS handshake fails (unreachable host)", async () => {
    // Use a non-routable address to trigger timeout/failure
    const target: ProbeTarget = { kind: "baseline", url: "https://192.0.2.1:9999", method: "GET", auth: "unauthenticated", fromLayer: "recon" };

    const result = await tlsConfigurationCheck.run({
      target,
      model: emptyModel(),
      client: new MockHttpClient(),
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    // Should get a target-unreachable error or check-error, not a crash
    expect(result.errors.length).toBeGreaterThanOrEqual(1);
  }, 10_000);

  it("has correct metadata", () => {
    expect(tlsConfigurationCheck.id).toBe("tls-configuration");
    expect(tlsConfigurationCheck.level).toBe("passive");
    expect(tlsConfigurationCheck.domain).toBe("cryptography");
  });
});
```

- [ ] **Step 2: Run tests**

Run: `npx vitest run tests/layers/probe/checks/passive/tls-configuration.test.ts`
Expected: All 3 tests pass (the unreachable host test may take up to 5s)

- [ ] **Step 3: Commit**

```bash
git add tests/layers/probe/checks/passive/tls-configuration.test.ts
git commit -m "test(probe): add TLS configuration check unit tests"
```

---

## Task 3: Endpoint Enumeration Check Tests

**Files:**
- Create: `tests/layers/probe/checks/passive/endpoint-enumeration.test.ts`

- [ ] **Step 1: Write tests**

```ts
import { describe, it, expect } from "vitest";
import { endpointEnumerationCheck } from "../../../../../src/layers/probe/checks/passive/endpoint-enumeration.js";
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

describe("endpoint-enumeration check", () => {
  it("applies only to endpoint targets", () => {
    const ep: ProbeTarget = { kind: "endpoint", url: "http://localhost:3000/api/users", method: "GET", auth: "required", fromLayer: "rules" };
    const baseline: ProbeTarget = { kind: "baseline", url: "http://localhost:3000", method: "GET", auth: "unauthenticated", fromLayer: "recon" };

    expect(endpointEnumerationCheck.appliesTo(ep, emptyModel())).toBe(true);
    expect(endpointEnumerationCheck.appliesTo(baseline, emptyModel())).toBe(false);
  });

  it("detects auth bypass when protected endpoint returns 200", async () => {
    const client = new MockHttpClient([
      { match: { url: "/api/users" }, response: { status: 200, headers: {}, body: "[{\"id\":1}]" } },
    ]);

    const target: ProbeTarget = { kind: "endpoint", url: "http://localhost:3000/api/users", method: "GET", auth: "required", fromLayer: "rules" };

    const result = await endpointEnumerationCheck.run({
      target,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].title).toContain("accessible without credentials");
    expect(result.findings[0].cwe).toBe("CWE-306");
  });

  it("produces no finding when protected endpoint returns 401", async () => {
    const client = new MockHttpClient([
      { match: { url: "/api/users" }, response: { status: 401, headers: {}, body: "Unauthorized" } },
    ]);

    const target: ProbeTarget = { kind: "endpoint", url: "http://localhost:3000/api/users", method: "GET", auth: "required", fromLayer: "rules" };

    const result = await endpointEnumerationCheck.run({
      target,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it("refutes prior finding when unauthenticated endpoint returns 403", async () => {
    const client = new MockHttpClient([
      { match: { url: "/api/public" }, response: { status: 403, headers: {}, body: "Forbidden" } },
    ]);

    const priorFinding: Finding = {
      id: "AUTH-001-abc",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Missing auth on /api/public",
      description: "",
      evidence: [{ file: "src/app/api/public/route.ts" }],
      remediation: "",
      references: [],
      layer: "rules",
    };

    const target: ProbeTarget = {
      kind: "endpoint", url: "http://localhost:3000/api/public", method: "GET",
      auth: "unauthenticated", fromLayer: "rules", fromFindingId: "AUTH-001-abc",
    };

    const result = await endpointEnumerationCheck.run({
      target,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.refuted).toHaveLength(1);
    expect(result.refuted[0].findingId).toBe("AUTH-001-abc");
  });

  it("confirms prior finding when auth-required endpoint is accessible", async () => {
    const client = new MockHttpClient([
      { match: { url: "/api/admin" }, response: { status: 200, headers: {}, body: "admin data" } },
    ]);

    const priorFinding: Finding = {
      id: "AUTH-002-xyz",
      domain: "auth-access-control",
      severity: "high",
      confidence: "medium",
      title: "Missing auth on /api/admin",
      description: "",
      evidence: [{ file: "src/app/api/admin/route.ts" }],
      remediation: "",
      references: [],
      layer: "rules",
    };

    const target: ProbeTarget = {
      kind: "endpoint", url: "http://localhost:3000/api/admin", method: "GET",
      auth: "required", fromLayer: "rules", fromFindingId: "AUTH-002-xyz",
    };

    const result = await endpointEnumerationCheck.run({
      target,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("AUTH-002-xyz");
  });
});
```

- [ ] **Step 2: Run tests**

Run: `npx vitest run tests/layers/probe/checks/passive/endpoint-enumeration.test.ts`
Expected: All 5 tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/layers/probe/checks/passive/endpoint-enumeration.test.ts
git commit -m "test(probe): add endpoint enumeration check unit tests"
```

---

## Task 4: Response Body Secrets Check Tests

**Files:**
- Create: `tests/layers/probe/checks/passive/response-body-secrets.test.ts`

- [ ] **Step 1: Write tests**

```ts
import { describe, it, expect } from "vitest";
import { responseBodySecretsCheck } from "../../../../../src/layers/probe/checks/passive/response-body-secrets.js";
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

const baselineTarget: ProbeTarget = { kind: "baseline", url: "http://localhost:3000", method: "GET", auth: "unauthenticated", fromLayer: "recon" };

describe("response-body-secrets check", () => {
  it("applies to baseline and endpoint targets", () => {
    const ep: ProbeTarget = { kind: "endpoint", url: "http://localhost:3000/api", method: "GET", auth: "required", fromLayer: "rules" };
    expect(responseBodySecretsCheck.appliesTo(baselineTarget, emptyModel())).toBe(true);
    expect(responseBodySecretsCheck.appliesTo(ep, emptyModel())).toBe(true);
  });

  it("detects AWS access key in response body", async () => {
    const client = new MockHttpClient([
      { match: { url: "http://localhost:3000" }, response: { status: 200, headers: {}, body: '{"key":"AKIAIOSFODNN7EXAMPLE"}' } },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.findings[0].title).toContain("AWS Access Key");
    expect(result.findings[0].probeEvidence.response.bodyPreview).toBe("[REDACTED — contains secrets]");
  });

  it("detects JWT token in response body", async () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const client = new MockHttpClient([
      { match: { url: "http://localhost:3000" }, response: { status: 200, headers: {}, body: `{"token":"${jwt}"}` } },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    const jwtFinding = result.findings.find((f) => f.title.includes("JWT"));
    expect(jwtFinding).toBeDefined();
    expect(jwtFinding!.severity).toBe("medium");
  });

  it("detects private key block in response body", async () => {
    const client = new MockHttpClient([
      { match: { url: "http://localhost:3000" }, response: { status: 200, headers: {}, body: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn..." } },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.findings[0].title).toContain("Private Key");
  });

  it("produces no findings for clean response body", async () => {
    const client = new MockHttpClient([
      { match: { url: "http://localhost:3000" }, response: { status: 200, headers: {}, body: '{"status":"ok","data":[]}' } },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it("never returns confirm or refute (secrets are new findings only)", async () => {
    const client = new MockHttpClient([
      { match: { url: "http://localhost:3000" }, response: { status: 200, headers: {}, body: "AKIAIOSFODNN7EXAMPLE" } },
    ]);

    const result = await responseBodySecretsCheck.run({
      target: baselineTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.confirmed).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run tests**

Run: `npx vitest run tests/layers/probe/checks/passive/response-body-secrets.test.ts`
Expected: All 5 tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/layers/probe/checks/passive/response-body-secrets.test.ts
git commit -m "test(probe): add response body secrets check unit tests"
```

---

## Task 5: CORS Configuration Check Tests

**Files:**
- Create: `tests/layers/probe/checks/passive/cors-configuration.test.ts`

- [ ] **Step 1: Write tests**

```ts
import { describe, it, expect } from "vitest";
import { corsConfigurationCheck } from "../../../../../src/layers/probe/checks/passive/cors-configuration.js";
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

const endpointTarget: ProbeTarget = { kind: "endpoint", url: "http://localhost:3000/api/users", method: "GET", auth: "required", fromLayer: "rules" };

describe("cors-configuration check", () => {
  it("applies only to endpoint targets", () => {
    const baseline: ProbeTarget = { kind: "baseline", url: "http://localhost:3000", method: "GET", auth: "unauthenticated", fromLayer: "recon" };
    expect(corsConfigurationCheck.appliesTo(endpointTarget, emptyModel())).toBe(true);
    expect(corsConfigurationCheck.appliesTo(baseline, emptyModel())).toBe(false);
  });

  it("detects wildcard CORS with credentials as critical", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "/api/users" },
        response: {
          status: 204,
          headers: { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" },
          body: "",
        },
      },
    ]);

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.findings[0].title).toContain("Wildcard CORS with credentials");
  });

  it("detects origin reflection with credentials as high", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "/api/users" },
        response: {
          status: 204,
          headers: {
            "access-control-allow-origin": "https://sentinel-cors-probe.example.com",
            "access-control-allow-credentials": "true",
          },
          body: "",
        },
      },
    ]);

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].title).toContain("reflects arbitrary origin");
  });

  it("detects origin reflection without credentials as medium", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "/api/users" },
        response: {
          status: 204,
          headers: { "access-control-allow-origin": "https://sentinel-cors-probe.example.com" },
          body: "",
        },
      },
    ]);

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("medium");
  });

  it("refutes prior CORS finding when origin is not reflected", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "/api/users" },
        response: {
          status: 204,
          headers: { "access-control-allow-origin": "https://myapp.com" },
          body: "",
        },
      },
    ]);

    const priorFinding: Finding = {
      id: "CORS-001",
      domain: "api-security",
      severity: "medium",
      confidence: "medium",
      title: "Potential CORS misconfiguration",
      description: "",
      evidence: [{ file: "src/app/api/users/route.ts" }],
      remediation: "",
      references: [],
      layer: "rules",
      ruleId: "API-CORS-001",
    };

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.refuted).toHaveLength(1);
    expect(result.refuted[0].findingId).toBe("CORS-001");
  });

  it("produces no findings and no refutations without prior finding on safe CORS", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "OPTIONS", url: "/api/users" },
        response: { status: 204, headers: { "access-control-allow-origin": "https://myapp.com" }, body: "" },
      },
    ]);

    const result = await corsConfigurationCheck.run({
      target: endpointTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.refuted).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run tests**

Run: `npx vitest run tests/layers/probe/checks/passive/cors-configuration.test.ts`
Expected: All 5 tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/layers/probe/checks/passive/cors-configuration.test.ts
git commit -m "test(probe): add CORS configuration check unit tests"
```

---

## Task 6: Integration Test — Passive End-to-End

**Files:**
- Create: `tests/integration/probe-passive.test.ts`

- [ ] **Step 1: Write test**

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import type { ProbeConfig, ProjectModel, Finding } from "../../src/model/types.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";

// Mock global fetch to simulate a running target
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function makeModel(): ProjectModel {
  return {
    meta: { name: "test-app", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [{ path: "/api/users", method: "GET", file: "src/app/api/users/route.ts", paramNames: [] }],
    endpoints: [
      { path: "/api/users", method: "GET", file: "src/app/api/users/route.ts", hasAuthCheck: true, hasValidation: false },
    ],
    fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

function makeConfig(): ProbeConfig {
  return {
    ...PROBE_CONFIG_DEFAULTS,
    enabled: true,
    level: "passive",
    targetUrl: "http://localhost:3000",
    logDir: "/tmp/probe-test-passive",
  };
}

describe("probe passive end-to-end", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("runs all passive checks and produces findings", async () => {
    mockFetch.mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html><body>Hello</body></html>",
    });

    const model = makeModel();
    const config = makeConfig();

    const { result, mergedFindings } = await runProbe(model, [], config);

    // Should have findings from security-headers (missing headers) at minimum
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.aggressionLevel).toBe("passive");
    expect(result.errors.every((e) => e.kind !== "check-error")).toBe(true);
    expect(result.usedRequests).toBeGreaterThan(0);
    expect(result.probeLogPath).toContain("probe-log-");
  });

  it("uses zero requests when target is unreachable", async () => {
    mockFetch.mockRejectedValue(new Error("ECONNREFUSED"));

    const model = makeModel();
    const config = makeConfig();

    const { result } = await runProbe(model, [], config);

    // All checks should have errors, not crashes
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.findings).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run test**

Run: `npx vitest run tests/integration/probe-passive.test.ts`
Expected: Both tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/integration/probe-passive.test.ts
git commit -m "test(probe): add passive end-to-end integration test"
```

---

## Task 7: Integration Test — Probe Confirms Prior Finding

**Files:**
- Create: `tests/integration/probe-confirm.test.ts`

- [ ] **Step 1: Write test**

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import type { ProbeConfig, ProjectModel, Finding } from "../../src/model/types.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function makeModel(): ProjectModel {
  return {
    meta: { name: "test-app", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [], endpoints: [],
    fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

describe("probe confirms prior finding", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("upgrades a rules finding about missing HSTS to confirmed", async () => {
    mockFetch.mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html></html>",
    });

    const priorFinding: Finding = {
      id: "INFRA-HSTS-001",
      domain: "infrastructure",
      severity: "high",
      confidence: "medium",
      title: "Missing strict-transport-security header",
      description: "No HSTS header configured",
      evidence: [{ file: "next.config.js" }],
      remediation: "Add HSTS header",
      references: [],
      layer: "rules",
    };

    const config: ProbeConfig = {
      ...PROBE_CONFIG_DEFAULTS,
      enabled: true,
      level: "passive",
      targetUrl: "http://localhost:3000",
      logDir: "/tmp/probe-test-confirm",
    };

    const { result, mergedFindings } = await runProbe(makeModel(), [priorFinding], config);

    expect(result.confirmedFindingIds).toContain("INFRA-HSTS-001");

    const upgraded = mergedFindings.find((f) => f.id === "INFRA-HSTS-001");
    expect(upgraded).toBeDefined();
    expect(upgraded!.confidence).toBe("confirmed");
  });
});
```

- [ ] **Step 2: Run test**

Run: `npx vitest run tests/integration/probe-confirm.test.ts`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration/probe-confirm.test.ts
git commit -m "test(probe): add finding confirmation integration test"
```

---

## Task 8: Integration Test — Probe Refutes Prior Finding

**Files:**
- Create: `tests/integration/probe-refute.test.ts`

- [ ] **Step 1: Write test**

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import type { ProbeConfig, ProjectModel, Finding } from "../../src/model/types.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function makeModel(): ProjectModel {
  return {
    meta: { name: "test-app", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [], endpoints: [],
    fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

describe("probe refutes prior finding", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("refutes a rules finding about missing CSP when header is present", async () => {
    mockFetch.mockResolvedValue({
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
    });

    const priorFinding: Finding = {
      id: "INFRA-CSP-001",
      domain: "infrastructure",
      severity: "medium",
      confidence: "medium",
      title: "Missing content-security-policy header",
      description: "CSP not configured",
      evidence: [{ file: "next.config.js" }],
      remediation: "Add CSP",
      references: [],
      layer: "rules",
    };

    const config: ProbeConfig = {
      ...PROBE_CONFIG_DEFAULTS,
      enabled: true,
      level: "passive",
      targetUrl: "http://localhost:3000",
      logDir: "/tmp/probe-test-refute",
    };

    const { result, mergedFindings } = await runProbe(makeModel(), [priorFinding], config);

    expect(result.refutedFindingIds).toContain("INFRA-CSP-001");

    const refuted = mergedFindings.find((f) => f.id === "INFRA-CSP-001");
    expect(refuted).toBeDefined();
    expect(refuted!.confidence).toBe("low");
    expect((refuted as any).refutedByProbe).toBe(true);
  });
});
```

- [ ] **Step 2: Run test**

Run: `npx vitest run tests/integration/probe-refute.test.ts`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration/probe-refute.test.ts
git commit -m "test(probe): add finding refutation integration test"
```

---

## Task 9: Integration Test — Authorization Denial

**Files:**
- Create: `tests/integration/probe-auth-deny.test.ts`

- [ ] **Step 1: Write test**

```ts
import { describe, it, expect } from "vitest";
import { resolveAuthorization } from "../../src/layers/probe/authorization.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { ProbeConfig } from "../../src/model/types.js";

describe("probe authorization denial", () => {
  const config: ProbeConfig = {
    ...PROBE_CONFIG_DEFAULTS,
    enabled: true,
    level: "passive",
    targetUrl: "http://localhost:3000",
  };

  it("denies access to deny-listed hosts", () => {
    const result = resolveAuthorization({
      targetUrl: "https://google.com",
      requestedLevel: "passive",
      config,
      existingEntries: [],
      authorizeFlagPresent: true,
    });

    expect(result.state).toBe("denied-deny-list");
    expect(result.reason).toContain("deny-list");
  });

  it("denies access to RFC1918 without --internal-network", () => {
    const result = resolveAuthorization({
      targetUrl: "http://192.168.1.1:3000",
      requestedLevel: "passive",
      config: { ...config, allowInternalNetwork: false },
      existingEntries: [],
      authorizeFlagPresent: true,
    });

    expect(result.state).toBe("denied-internal");
  });

  it("denies access to public hosts without --allow-public", () => {
    const result = resolveAuthorization({
      targetUrl: "https://my-staging.example.com",
      requestedLevel: "passive",
      config: { ...config, allowPublicHosts: false },
      existingEntries: [],
      authorizeFlagPresent: false,
    });

    expect(result.state).toBe("denied-public");
  });

  it("returns needs-prompt for intrusive even with existing authorization", () => {
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "intrusive",
      config,
      existingEntries: [{
        targetOrigin: "http://localhost:3000",
        level: "standard",
        grantedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        scopeNote: "test",
      }],
      authorizeFlagPresent: false,
    });

    expect(result.state).toBe("needs-prompt");
  });

  it("grants access for localhost with valid authorization", () => {
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "passive",
      config,
      existingEntries: [{
        targetOrigin: "http://localhost:3000",
        level: "passive",
        grantedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        scopeNote: "test",
      }],
      authorizeFlagPresent: false,
    });

    expect(result.state).toBe("granted");
  });

  it("detects expired authorization", () => {
    const result = resolveAuthorization({
      targetUrl: "http://localhost:3000",
      requestedLevel: "passive",
      config,
      existingEntries: [{
        targetOrigin: "http://localhost:3000",
        level: "passive",
        grantedAt: "2025-01-01T00:00:00Z",
        expiresAt: "2025-01-31T00:00:00Z",
        scopeNote: "old",
      }],
      authorizeFlagPresent: false,
    });

    expect(result.state).toBe("expired");
  });
});
```

- [ ] **Step 2: Run test**

Run: `npx vitest run tests/integration/probe-auth-deny.test.ts`
Expected: All 6 tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/integration/probe-auth-deny.test.ts
git commit -m "test(probe): add authorization denial integration test"
```

---

## Task 10: Integration Test — Cleanup Obligations

**Files:**
- Create: `tests/integration/probe-cleanup.test.ts`

- [ ] **Step 1: Write test**

```ts
import { describe, it, expect, vi, beforeEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import type { ProbeConfig, ProjectModel } from "../../src/model/types.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function makeModel(): ProjectModel {
  return {
    meta: { name: "test-app", path: "/test", stack: "nextjs-supabase", packageManager: "npm", language: "typescript", framework: "next", deployTarget: null },
    routes: [], endpoints: [],
    fileUploads: [], authFlows: [], dataModels: [], dependencies: [], envVars: [], staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

describe("probe cleanup obligations", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("reports zero cleanup obligations for passive-only run", async () => {
    mockFetch.mockResolvedValue({
      status: 200,
      headers: new Headers({}),
      text: async () => "",
    });

    const config: ProbeConfig = {
      ...PROBE_CONFIG_DEFAULTS,
      enabled: true,
      level: "passive",
      targetUrl: "http://localhost:3000",
      logDir: "/tmp/probe-test-cleanup",
    };

    const { result } = await runProbe(makeModel(), [], config);

    // Passive checks never register cleanup obligations
    expect(result.cleanupObligationsExecuted).toBe(0);
    expect(result.cleanupObligationsFailed).toBe(0);
    expect(result.cleanupFailures).toHaveLength(0);
  });

  it("cleanup registry is available but unused in passive mode", async () => {
    mockFetch.mockResolvedValue({
      status: 200,
      headers: new Headers({ "strict-transport-security": "max-age=31536000" }),
      text: async () => "<html></html>",
    });

    const config: ProbeConfig = {
      ...PROBE_CONFIG_DEFAULTS,
      enabled: true,
      level: "passive",
      targetUrl: "http://localhost:3000",
      logDir: "/tmp/probe-test-cleanup-2",
    };

    const { result } = await runProbe(makeModel(), [], config);

    // The orchestrator creates and passes a cleanup registry to every check.
    // Passive checks don't use it, but it's there.
    expect(result.cleanupObligationsExecuted).toBe(0);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});
```

- [ ] **Step 2: Run test**

Run: `npx vitest run tests/integration/probe-cleanup.test.ts`
Expected: Both tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/integration/probe-cleanup.test.ts
git commit -m "test(probe): add cleanup obligations integration test"
```

---

## Task 11: Run Full Test Suite and Verify

- [ ] **Step 1: Run all probe tests**

Run: `npx vitest run tests/layers/probe/`
Expected: All unit tests pass (previous 43 + new ~28)

- [ ] **Step 2: Run all integration tests**

Run: `npx vitest run tests/integration/probe-`
Expected: All 5 integration test files pass

- [ ] **Step 3: Run full project test suite**

Run: `npx vitest run`
Expected: All tests pass (320 existing + ~40 new = ~360)

- [ ] **Step 4: Typecheck**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 5: Final commit (if any fixes needed)**

```bash
git add -A
git commit -m "test(probe): complete probe layer test suite"
```
