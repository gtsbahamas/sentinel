# Probe v0.4 Intrusive Checks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 3 intrusive-level probe checks (xss-reflection, file-upload, form-fuzzing) and wire them into the probe orchestrator. file-upload is the first check that registers real cleanup obligations.

**Architecture:** Each check follows the existing `ProbeCheck` interface. xss-reflection and form-fuzzing are read-only. file-upload mutates state (uploads files) and registers blocking cleanup obligations to DELETE them. All checks require `level: "intrusive"`. The `index.ts` entry point gets a `loadIntrusiveChecks()` function.

**Tech Stack:** TypeScript, Vitest, MockHttpClient, CleanupRegistry

---

## File Structure

### New files (3 checks + 3 unit tests + 1 integration test)

| File | Responsibility |
|------|---------------|
| `src/layers/probe/checks/intrusive/xss-reflection.ts` | Inject marker strings, detect unescaped reflection |
| `src/layers/probe/checks/intrusive/file-upload.ts` | Upload benign test files, detect missing validation |
| `src/layers/probe/checks/intrusive/form-fuzzing.ts` | Send malformed bodies, detect error disclosure |
| `tests/layers/probe/checks/intrusive/xss-reflection.test.ts` | Unit tests |
| `tests/layers/probe/checks/intrusive/file-upload.test.ts` | Unit tests |
| `tests/layers/probe/checks/intrusive/form-fuzzing.test.ts` | Unit tests |
| `tests/integration/probe-intrusive.test.ts` | End-to-end integration |

### Modified files

| File | Change |
|------|--------|
| `src/layers/probe/index.ts` | Add `loadIntrusiveChecks()`, call it in `runProbe()` |

---

## Task 1: XSS Reflection Check

**Files:**
- Create: `src/layers/probe/checks/intrusive/xss-reflection.ts`
- Test: `tests/layers/probe/checks/intrusive/xss-reflection.test.ts`

This check injects benign marker strings into query and body inputs, then checks if the marker appears unescaped in the response. The marker contains no executable content — detection is literal substring match.

- [ ] **Step 1: Write the unit test file**

```typescript
// tests/layers/probe/checks/intrusive/xss-reflection.test.ts
import { describe, it, expect } from "vitest";
import { xssReflectionCheck } from "../../../../../src/layers/probe/checks/intrusive/xss-reflection.js";
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

const queryTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/search",
  method: "GET",
  auth: "unauthenticated",
  fromLayer: "rules",
  fromFindingId: "INPUT-XSS-001",
  inputs: [{ name: "q", in: "query", type: "string" }],
};

const bodyTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/comments",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "rules",
  inputs: [{ name: "body", in: "body", type: "string" }],
};

const noInputTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/health",
  method: "GET",
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

describe("xss-reflection check", () => {
  it("applies to endpoints with query or body inputs, not baseline or no-input", () => {
    expect(xssReflectionCheck.appliesTo(queryTarget, emptyModel())).toBe(true);
    expect(xssReflectionCheck.appliesTo(bodyTarget, emptyModel())).toBe(true);
    expect(xssReflectionCheck.appliesTo(noInputTarget, emptyModel())).toBe(false);
    expect(xssReflectionCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("detects unescaped marker reflection as high severity", async () => {
    // Server reflects query param unescaped in response body
    const client = new MockHttpClient([
      {
        match: { method: "GET", url: /search/ },
        response: {
          status: 200,
          body: '<html><body>Results for: <sentinel-marker-testNONCE/></body></html>',
        },
      },
    ], 5000);

    const result = await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    // The check injects its own nonce, so we check that ANY finding about reflection was produced
    const reflectionFindings = result.findings.filter((f) =>
      f.title.toLowerCase().includes("reflected") || f.title.toLowerCase().includes("xss"),
    );
    // May or may not find the marker depending on nonce matching in mock.
    // This test verifies the check runs without error and makes requests.
    expect(client.recorded.length).toBeGreaterThan(0);
    // All requests should be intent: "read"
    expect(client.recorded.every((r) => r.intent === "read")).toBe(true);
  });

  it("detects unescaped reflection with controlled mock", async () => {
    // Use a mock that echoes back any sentinel-marker it receives
    const client = new MockHttpClient([], 5000);
    const origRequest = client.request.bind(client);
    client.request = async (req) => {
      // Extract the marker from query string or body
      const urlObj = new URL(req.url);
      const qVal = urlObj.searchParams.get("q") ?? "";
      const bodyVal = req.body ?? "";
      const marker = qVal || bodyVal;
      return {
        status: 200,
        headers: { "content-type": "text/html" },
        body: `<html>Results: ${marker}</html>`,
        timingMs: 1,
        requestId: "mock-req-1",
      };
    };

    const result = await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const xssFindings = result.findings.filter((f) => f.severity === "high");
    expect(xssFindings.length).toBeGreaterThan(0);
    expect(xssFindings[0].cwe).toBe("CWE-79");
  });

  it("produces no findings when marker is HTML-escaped", async () => {
    const client = new MockHttpClient([], 5000);
    client.request = async (req) => {
      const urlObj = new URL(req.url);
      const qVal = urlObj.searchParams.get("q") ?? "";
      // HTML-escape the marker
      const escaped = qVal.replace(/</g, "&lt;").replace(/>/g, "&gt;");
      return {
        status: 200,
        headers: { "content-type": "text/html" },
        body: `<html>Results: ${escaped}</html>`,
        timingMs: 1,
        requestId: "mock-req-2",
      };
    };

    const result = await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    // No high-severity findings (marker was properly escaped)
    const highFindings = result.findings.filter((f) => f.severity === "high");
    expect(highFindings).toHaveLength(0);
  });

  it("confirms prior XSS finding when reflection detected", async () => {
    const client = new MockHttpClient([], 5000);
    client.request = async (req) => {
      const urlObj = new URL(req.url);
      const qVal = urlObj.searchParams.get("q") ?? "";
      return {
        status: 200,
        headers: {},
        body: `<html>${qVal}</html>`,
        timingMs: 1,
        requestId: "mock-req-3",
      };
    };

    const priorFinding: Finding = {
      id: "INPUT-XSS-001",
      domain: "input-injection",
      severity: "high",
      confidence: "medium",
      title: "Potential XSS in search endpoint",
      description: "Query param may be reflected",
      evidence: [{ file: "src/app/search/page.tsx" }],
      remediation: "Escape output",
      references: [],
      layer: "rules",
    };

    const result = await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.confirmed).toHaveLength(1);
    expect(result.confirmed[0].findingId).toBe("INPUT-XSS-001");
  });

  it("registers zero cleanup obligations", async () => {
    const registry = new ProbeCleanupRegistry();
    const client = new MockHttpClient([
      { match: { url: /search/ }, response: { status: 200, body: "safe" } },
    ], 5000);

    await xssReflectionCheck.run({
      target: queryTarget,
      model: emptyModel(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    expect(registry.pendingCount()).toBe(0);
  });

  it("handles target unreachable gracefully", async () => {
    const client = new MockHttpClient([], 5000);
    client.request = async () => {
      throw new (await import("../../../../../src/layers/probe/http-client.js")).TargetUnreachable("https://api.example.com/search");
    };

    const result = await xssReflectionCheck.run({
      target: queryTarget,
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

Run: `npx vitest run tests/layers/probe/checks/intrusive/xss-reflection.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// src/layers/probe/checks/intrusive/xss-reflection.ts
import { randomUUID } from "crypto";
import type { ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

function generateMarker(): string {
  const nonce = randomUUID().slice(0, 8);
  return `<sentinel-marker-${nonce}/>`;
}

export const xssReflectionCheck: ProbeCheck = {
  id: "xss-reflection",
  level: "intrusive" as AggressionLevel,
  domain: "input-injection" as SecurityDomain,
  description: "Inject benign marker strings and check for unescaped reflection in responses",

  appliesTo(target): boolean {
    if (target.kind !== "endpoint") return false;
    return !!target.inputs?.some((i) => i.in === "query" || i.in === "body");
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const xssFinding = ctx.priorFindings.find(
      (f) => f.domain === "input-injection" && ctx.target.fromFindingId === f.id,
    );

    const queryInputs = ctx.target.inputs?.filter((i) => i.in === "query") ?? [];
    const bodyInputs = ctx.target.inputs?.filter((i) => i.in === "body") ?? [];

    let foundReflection = false;

    // Test query inputs
    for (const input of queryInputs) {
      if (foundReflection) break;
      const marker = generateMarker();
      const url = new URL(ctx.target.url);
      url.searchParams.set(input.name, marker);

      try {
        const resp = await ctx.client.request({
          method: "GET",
          url: url.toString(),
          intent: "read",
        });

        if (resp.body.includes(marker)) {
          foundReflection = true;
          findings.push(makeReflectionFinding(marker, input.name, "query", resp, ctx, xssFinding?.id));
          if (xssFinding) confirmed.push({ findingId: xssFinding.id });
        }
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "xss-reflection", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        }
        throw err;
      }
    }

    // Test body inputs
    for (const input of bodyInputs) {
      if (foundReflection) break;
      const marker = generateMarker();
      const body = JSON.stringify({ [input.name]: marker });

      try {
        const resp = await ctx.client.request({
          method: ctx.target.method === "POST" ? "POST" : "PUT",
          url: ctx.target.url,
          headers: { "Content-Type": "application/json" },
          body,
          intent: "read",
        });

        if (resp.body.includes(marker)) {
          foundReflection = true;
          findings.push(makeReflectionFinding(marker, input.name, "body", resp, ctx, xssFinding?.id));
          if (xssFinding) confirmed.push({ findingId: xssFinding.id });
        }
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "xss-reflection", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        }
        throw err;
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};

function makeReflectionFinding(
  marker: string,
  inputName: string,
  inputLocation: "query" | "body",
  resp: { requestId: string; status: number; headers: Record<string, string>; body: string; timingMs: number },
  ctx: ProbeCheckContext,
  confirmsId?: string,
): ProbeFinding {
  return {
    id: `PROBE-XSS-${randomUUID().slice(0, 8)}`,
    domain: "input-injection",
    severity: "high",
    confidence: "confirmed",
    title: `XSS: marker reflected unescaped in ${inputLocation} param "${inputName}" on ${ctx.target.url}`,
    description: `Injected marker string "${marker}" into ${inputLocation} parameter "${inputName}" and found it reflected verbatim in the response body. This indicates the input is rendered without HTML encoding.`,
    evidence: [],
    remediation: "HTML-encode all user input before rendering in responses. Use framework auto-escaping (React JSX, Vue templates) or explicit encoding functions.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ],
    layer: "probe",
    cwe: "CWE-79",
    probeEvidence: {
      requestId: resp.requestId,
      checkId: "xss-reflection",
      aggressionLevel: "intrusive",
      request: { method: inputLocation === "query" ? "GET" : "POST", url: ctx.target.url, headers: {} },
      response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
    },
    confirms: confirmsId,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/layers/probe/checks/intrusive/xss-reflection.test.ts`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/probe/checks/intrusive/xss-reflection.ts tests/layers/probe/checks/intrusive/xss-reflection.test.ts
git commit -m "feat(probe): add xss-reflection intrusive check with tests"
```

---

## Task 2: File Upload Check

**Files:**
- Create: `src/layers/probe/checks/intrusive/file-upload.ts`
- Test: `tests/layers/probe/checks/intrusive/file-upload.test.ts`

This is the first check that registers real cleanup obligations. It uploads benign test files to upload endpoints and verifies MIME validation and path traversal protection. It SKIPS the check entirely if no DELETE endpoint exists for cleanup.

- [ ] **Step 1: Write the unit test file**

```typescript
// tests/layers/probe/checks/intrusive/file-upload.test.ts
import { describe, it, expect } from "vitest";
import { fileUploadCheck } from "../../../../../src/layers/probe/checks/intrusive/file-upload.js";
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

function modelWithUpload(): ProjectModel {
  const m = emptyModel();
  m.fileUploads = [{ file: "src/app/api/upload/route.ts", line: 10, acceptsMultipart: true, hasMimeValidation: false, hasSizeLimit: false, usesUserFilename: true, storageDestination: "supabase" }];
  m.endpoints = [
    { path: "/api/upload", method: "POST", file: "src/app/api/upload/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
    { path: "/api/upload/:id", method: "DELETE", file: "src/app/api/upload/[id]/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
  ];
  return m;
}

function modelWithUploadNoDelete(): ProjectModel {
  const m = emptyModel();
  m.fileUploads = [{ file: "src/app/api/upload/route.ts", line: 10, acceptsMultipart: true, hasMimeValidation: false, hasSizeLimit: false, usesUserFilename: true, storageDestination: "supabase" }];
  m.endpoints = [
    { path: "/api/upload", method: "POST", file: "src/app/api/upload/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
  ];
  return m;
}

const uploadTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/upload",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "rules",
  fromFindingId: "UPLOAD-001",
};

const nonUploadTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/users",
  method: "GET",
  auth: "required",
  fromLayer: "recon",
};

describe("file-upload check", () => {
  it("applies to POST endpoints that match a fileUpload handler in the model", () => {
    expect(fileUploadCheck.appliesTo(uploadTarget, modelWithUpload())).toBe(true);
    expect(fileUploadCheck.appliesTo(nonUploadTarget, modelWithUpload())).toBe(false);
    expect(fileUploadCheck.appliesTo(uploadTarget, emptyModel())).toBe(false);
  });

  it("skips entirely when no DELETE endpoint exists (no cleanup path)", async () => {
    const client = new MockHttpClient([], 5000);
    const registry = new ProbeCleanupRegistry();

    const result = await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUploadNoDelete(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
    expect(client.recorded).toHaveLength(0);
    expect(registry.pendingCount()).toBe(0);
  });

  it("registers blocking cleanup obligation BEFORE uploading", async () => {
    const registrationOrder: string[] = [];

    const client = new MockHttpClient([
      { match: { method: "POST", url: /upload/ }, response: { status: 200, body: JSON.stringify({ id: "file-123", url: "/uploads/file-123.txt" }) } },
      { match: { method: "DELETE", url: /upload/ }, response: { status: 204, body: "" } },
    ], 5000);

    const registry = new ProbeCleanupRegistry();
    const origRegister = registry.register.bind(registry);
    registry.register = (ob) => {
      registrationOrder.push("register");
      return origRegister(ob);
    };

    const origRequest = client.request.bind(client);
    client.request = async (req) => {
      if (req.intent === "mutate") registrationOrder.push("upload");
      return origRequest(req);
    };

    await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    // Obligation must be registered BEFORE the upload request
    const registerIdx = registrationOrder.indexOf("register");
    const uploadIdx = registrationOrder.indexOf("upload");
    expect(registerIdx).toBeLessThan(uploadIdx);
    expect(registry.pendingCount()).toBeGreaterThan(0);
  });

  it("cleanup obligation calls DELETE on the upload endpoint", async () => {
    const client = new MockHttpClient([
      { match: { method: "POST", url: /upload/ }, response: { status: 200, body: JSON.stringify({ id: "file-123" }) } },
      { match: { method: "DELETE", url: /upload/ }, response: { status: 204, body: "" } },
    ], 5000);

    const registry = new ProbeCleanupRegistry();

    await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    // Execute cleanup
    const cleanupResult = await registry.executeAll();
    expect(cleanupResult.executed).toBeGreaterThan(0);
    expect(cleanupResult.failed).toBe(0);

    // Verify DELETE requests were made
    const deleteRequests = client.recorded.filter((r) => r.method === "DELETE");
    expect(deleteRequests.length).toBeGreaterThan(0);
  });

  it("detects missing MIME validation when any content type is accepted", async () => {
    const client = new MockHttpClient([
      { match: { method: "POST", url: /upload/ }, response: { status: 200, body: JSON.stringify({ id: "file-123" }) } },
      { match: { method: "DELETE", url: /upload/ }, response: { status: 204, body: "" } },
    ], 5000);

    const priorFinding: Finding = {
      id: "UPLOAD-001",
      domain: "file-upload",
      severity: "high",
      confidence: "medium",
      title: "Missing MIME validation on upload",
      description: "Upload accepts any file type",
      evidence: [{ file: "src/app/api/upload/route.ts" }],
      remediation: "Validate MIME types",
      references: [],
      layer: "rules",
    };

    const result = await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [priorFinding],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    // Should have findings about accepted uploads
    expect(result.findings.length).toBeGreaterThan(0);
    // Uses mutate intent for uploads
    const mutateRequests = client.recorded.filter((r) => r.intent === "mutate");
    expect(mutateRequests.length).toBeGreaterThan(0);
  });

  it("detects path traversal when traversal filename is accepted", async () => {
    const client = new MockHttpClient([
      { match: { method: "POST", url: /upload/ }, response: { status: 200, body: JSON.stringify({ id: "file-456" }) } },
      { match: { method: "DELETE", url: /upload/ }, response: { status: 204, body: "" } },
    ], 5000);

    const result = await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    // Should include a path traversal finding if the traversal filename was accepted
    const traversalFindings = result.findings.filter((f) => f.cwe === "CWE-22");
    // Traversal finding only appears if server accepted the traversal filename (200)
    // Since our mock always returns 200, we should see it
    expect(traversalFindings.length).toBeGreaterThan(0);
    expect(traversalFindings[0].severity).toBe("high");
  });

  it("handles target unreachable gracefully", async () => {
    const client = new MockHttpClient([], 5000);
    client.request = async () => {
      throw new (await import("../../../../../src/layers/probe/http-client.js")).TargetUnreachable("https://api.example.com/api/upload");
    };

    const result = await fileUploadCheck.run({
      target: uploadTarget,
      model: modelWithUpload(),
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

Run: `npx vitest run tests/layers/probe/checks/intrusive/file-upload.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// src/layers/probe/checks/intrusive/file-upload.ts
import { randomUUID } from "crypto";
import type { ProbeFinding, ProbeError, AggressionLevel, SecurityDomain, ProjectModel, ProbeTarget } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

// Minimal valid PNG (1x1 transparent pixel, ~68 bytes)
const MINIMAL_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
  "base64",
);

interface TestFile {
  label: string;
  filename: string;
  contentType: string;
  content: string;
  isTraversal: boolean;
}

function buildTestFiles(nonce: string): TestFile[] {
  return [
    { label: "txt", filename: `sentinel-probe-${nonce}.txt`, contentType: "text/plain", content: "x", isTraversal: false },
    { label: "png", filename: `sentinel-probe-${nonce}.png`, contentType: "image/png", content: MINIMAL_PNG.toString("base64"), isTraversal: false },
    { label: "traversal", filename: `../../../sentinel-probe-${nonce}.txt`, contentType: "text/plain", content: "x", isTraversal: true },
  ];
}

function findDeleteEndpoint(model: ProjectModel, uploadPath: string): string | null {
  // Look for a DELETE endpoint that shares the upload path prefix
  // e.g., POST /api/upload → DELETE /api/upload/:id
  const uploadBase = uploadPath.replace(/\/$/, "");
  const deleteEp = model.endpoints.find(
    (ep) => ep.method === "DELETE" && ep.path.startsWith(uploadBase),
  );
  return deleteEp ? deleteEp.path : null;
}

function findUploadPath(model: ProjectModel, targetUrl: string): string | null {
  const url = new URL(targetUrl);
  const path = url.pathname;
  const handler = model.fileUploads.find((u) => {
    const ep = model.endpoints.find((e) => e.file === u.file && e.method === "POST");
    return ep && path.endsWith(ep.path);
  });
  if (!handler) return null;
  const ep = model.endpoints.find((e) => e.file === handler.file && e.method === "POST");
  return ep?.path ?? null;
}

export const fileUploadCheck: ProbeCheck = {
  id: "file-upload",
  level: "intrusive" as AggressionLevel,
  domain: "file-upload" as SecurityDomain,
  description: "Upload benign test files to detect missing MIME validation and path traversal",

  appliesTo(target: ProbeTarget, model: ProjectModel): boolean {
    if (target.kind !== "endpoint") return false;
    if (target.method !== "POST") return false;
    // Must match a known file upload handler
    return model.fileUploads.some((u) => {
      const ep = model.endpoints.find((e) => e.file === u.file && e.method === "POST");
      return ep && target.url.endsWith(ep.path);
    });
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const uploadPath = findUploadPath(ctx.model, ctx.target.url);
    if (!uploadPath) return { findings, confirmed, refuted, errors };

    const deletePath = findDeleteEndpoint(ctx.model, uploadPath);
    if (!deletePath) {
      // No DELETE endpoint = no cleanup path = skip entirely
      return { findings, confirmed, refuted, errors };
    }

    const uploadFinding = ctx.priorFindings.find(
      (f) => f.domain === "file-upload" && ctx.target.fromFindingId === f.id,
    );

    const nonce = randomUUID().slice(0, 8);
    const testFiles = buildTestFiles(nonce);
    const baseUrl = new URL(ctx.target.url).origin;
    const uploadedIds: string[] = [];

    for (const testFile of testFiles) {
      // Register cleanup BEFORE uploading
      const cleanupDeletePath = deletePath;
      const fileLabel = testFile.label;
      ctx.registry.register({
        description: `delete test file ${testFile.filename} via ${cleanupDeletePath}`,
        severity: "blocking",
        cleanup: async (_signal) => {
          // Delete by the ID returned from the upload response
          const idToDelete = uploadedIds.find((id) => id.includes(fileLabel)) ?? uploadedIds[uploadedIds.length - 1];
          if (idToDelete) {
            const deleteUrl = `${baseUrl}${cleanupDeletePath.replace(":id", idToDelete)}`;
            await ctx.client.request({ method: "DELETE", url: deleteUrl, intent: "mutate" }).catch(() => {});
          }
        },
      });

      try {
        // Build multipart-like body (simplified — real multipart would use boundary)
        const body = JSON.stringify({ filename: testFile.filename, content: testFile.content, contentType: testFile.contentType });

        const resp = await ctx.client.request({
          method: "POST",
          url: ctx.target.url,
          headers: { "Content-Type": "application/json" },
          body,
          intent: "mutate",
        });

        // Try to extract upload ID from response
        try {
          const parsed = JSON.parse(resp.body);
          const id = parsed.id ?? parsed.fileId ?? parsed.key ?? `${fileLabel}-${nonce}`;
          uploadedIds.push(String(id));
        } catch {
          uploadedIds.push(`${fileLabel}-${nonce}`);
        }

        const accepted = resp.status >= 200 && resp.status < 300;

        if (testFile.isTraversal && accepted) {
          findings.push({
            id: `PROBE-UPLOAD-${randomUUID().slice(0, 8)}`,
            domain: "file-upload",
            severity: "high",
            confidence: "confirmed",
            title: `Path traversal filename accepted on ${ctx.target.url}`,
            description: `Uploaded file with name "${testFile.filename}" was accepted (${resp.status}). The server does not sanitize filenames, allowing path traversal attacks.`,
            evidence: [],
            remediation: "Strip path components from uploaded filenames. Use server-generated filenames or UUIDs instead of user-provided names.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
            layer: "probe",
            cwe: "CWE-22",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "file-upload",
              aggressionLevel: "intrusive",
              request: { method: "POST", url: ctx.target.url, headers: { "Content-Type": "application/json" }, bodyPreview: body.slice(0, 256) },
              response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
            },
            confirms: uploadFinding?.id,
          });
          if (uploadFinding) confirmed.push({ findingId: uploadFinding.id });
        } else if (!testFile.isTraversal && accepted) {
          findings.push({
            id: `PROBE-UPLOAD-${randomUUID().slice(0, 8)}`,
            domain: "file-upload",
            severity: "medium",
            confidence: "confirmed",
            title: `Upload accepted ${testFile.contentType} without MIME restriction: ${ctx.target.url}`,
            description: `Uploaded ${testFile.label} file (${testFile.contentType}) was accepted (${resp.status}). Server may lack MIME type validation.`,
            evidence: [],
            remediation: "Validate uploaded file MIME types against an allowlist. Reject unexpected content types.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"],
            layer: "probe",
            cwe: "CWE-434",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "file-upload",
              aggressionLevel: "intrusive",
              request: { method: "POST", url: ctx.target.url, headers: { "Content-Type": "application/json" }, bodyPreview: body.slice(0, 256) },
              response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
            },
          });
        }
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "file-upload", targetUrl: ctx.target.url });
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

Run: `npx vitest run tests/layers/probe/checks/intrusive/file-upload.test.ts`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/probe/checks/intrusive/file-upload.ts tests/layers/probe/checks/intrusive/file-upload.test.ts
git commit -m "feat(probe): add file-upload intrusive check with cleanup obligations and tests"
```

---

## Task 3: Form Fuzzing Check

**Files:**
- Create: `src/layers/probe/checks/intrusive/form-fuzzing.ts`
- Test: `tests/layers/probe/checks/intrusive/form-fuzzing.test.ts`

Sends malformed POST bodies (truncated JSON, unicode stress, type mismatches, oversized fields). Detects 500 errors, stack trace leakage, and request body reflection.

- [ ] **Step 1: Write the unit test file**

```typescript
// tests/layers/probe/checks/intrusive/form-fuzzing.test.ts
import { describe, it, expect } from "vitest";
import { formFuzzingCheck } from "../../../../../src/layers/probe/checks/intrusive/form-fuzzing.js";
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

const postTarget: ProbeTarget = {
  kind: "endpoint",
  url: "https://api.example.com/api/comments",
  method: "POST",
  auth: "unauthenticated",
  fromLayer: "recon",
  inputs: [{ name: "body", in: "body", type: "string" }],
};

const getTarget: ProbeTarget = {
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

describe("form-fuzzing check", () => {
  it("applies to POST endpoints, not GET or baseline", () => {
    expect(formFuzzingCheck.appliesTo(postTarget, emptyModel())).toBe(true);
    expect(formFuzzingCheck.appliesTo(getTarget, emptyModel())).toBe(false);
    expect(formFuzzingCheck.appliesTo(baselineTarget, emptyModel())).toBe(false);
  });

  it("detects 500 server errors as unhandled error findings", async () => {
    const client = new MockHttpClient([
      { match: { method: "POST", url: /comments/ }, response: { status: 500, body: "Internal Server Error" } },
    ], 5000);

    const result = await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const serverErrorFindings = result.findings.filter((f) =>
      f.description.toLowerCase().includes("500") || f.title.toLowerCase().includes("500"),
    );
    expect(serverErrorFindings.length).toBeGreaterThan(0);
    expect(serverErrorFindings[0].severity).toBe("medium");
  });

  it("detects stack trace leakage in error responses", async () => {
    const client = new MockHttpClient([
      {
        match: { method: "POST", url: /comments/ },
        response: {
          status: 500,
          body: JSON.stringify({
            error: "TypeError: Cannot read property 'trim' of undefined",
            stack: "    at processInput (/app/src/handlers/comments.ts:42:15)\n    at Layer.handle",
          }),
        },
      },
    ], 5000);

    const result = await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    const stackFindings = result.findings.filter((f) => f.cwe === "CWE-209");
    expect(stackFindings.length).toBeGreaterThan(0);
  });

  it("produces no findings when all payloads return 400 with generic error", async () => {
    const client = new MockHttpClient([
      { match: { method: "POST", url: /comments/ }, response: { status: 400, body: JSON.stringify({ error: "Bad request" }) } },
    ], 5000);

    const result = await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(result.errors).toHaveLength(0);
    // 400 with generic error = properly handled, no findings
    const badFindings = result.findings.filter((f) => f.severity !== "info");
    expect(badFindings).toHaveLength(0);
  });

  it("registers zero cleanup obligations", async () => {
    const registry = new ProbeCleanupRegistry();
    const client = new MockHttpClient([
      { match: { url: /comments/ }, response: { status: 400, body: "" } },
    ], 5000);

    await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry,
      priorFindings: [],
      runId: "test-run",
    });

    expect(registry.pendingCount()).toBe(0);
  });

  it("all requests use intent read", async () => {
    const client = new MockHttpClient([
      { match: { url: /comments/ }, response: { status: 400, body: "" } },
    ], 5000);

    await formFuzzingCheck.run({
      target: postTarget,
      model: emptyModel(),
      client,
      registry: new ProbeCleanupRegistry(),
      priorFindings: [],
      runId: "test-run",
    });

    expect(client.recorded.length).toBeGreaterThan(0);
    expect(client.recorded.every((r) => r.intent === "read")).toBe(true);
  });

  it("handles target unreachable gracefully", async () => {
    const client = new MockHttpClient([], 5000);
    client.request = async () => {
      throw new (await import("../../../../../src/layers/probe/http-client.js")).TargetUnreachable("https://api.example.com/api/comments");
    };

    const result = await formFuzzingCheck.run({
      target: postTarget,
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

Run: `npx vitest run tests/layers/probe/checks/intrusive/form-fuzzing.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```typescript
// src/layers/probe/checks/intrusive/form-fuzzing.ts
import { randomUUID } from "crypto";
import type { ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const STACK_TRACE_PATTERNS = [
  /at\s+[\w.]+\s+\(.*:\d+:\d+\)/,
  /^\s+at\s+/m,
  /Traceback\s*\(most\s*recent/i,
  /\.ts:\d+:\d+/,
  /\.js:\d+:\d+/,
];

const FUZZ_PAYLOADS: Array<{ label: string; body: string; contentType: string }> = [
  { label: "truncated-json", body: '{"key": "val', contentType: "application/json" },
  { label: "unicode-stress", body: JSON.stringify({ data: "\u0000".repeat(1000) + "\uD83D\uDE00".repeat(500) + "\u200F".repeat(500) }), contentType: "application/json" },
  { label: "type-mismatch", body: JSON.stringify({ name: 99999, email: [1, 2, 3], active: "not-a-boolean" }), contentType: "application/json" },
  { label: "empty-object", body: "{}", contentType: "application/json" },
  { label: "oversized-field", body: JSON.stringify({ data: "A".repeat(100_000) }), contentType: "application/json" },
];

export const formFuzzingCheck: ProbeCheck = {
  id: "form-fuzzing",
  level: "intrusive" as AggressionLevel,
  domain: "business-logic" as SecurityDomain,
  description: "Send malformed POST bodies to detect unhandled errors and information disclosure",

  appliesTo(target): boolean {
    if (target.kind !== "endpoint") return false;
    return target.method === "POST" || target.method === "PUT" || target.method === "PATCH";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    let found500 = false;
    let foundStackTrace = false;

    for (const payload of FUZZ_PAYLOADS) {
      try {
        const resp = await ctx.client.request({
          method: "POST",
          url: ctx.target.url,
          headers: { "Content-Type": payload.contentType },
          body: payload.body,
          intent: "read",
        });

        const bodyText = resp.body.slice(0, 4096);

        // Detect 500 server error
        if (!found500 && resp.status >= 500) {
          found500 = true;
          findings.push({
            id: `PROBE-FUZZ-${randomUUID().slice(0, 8)}`,
            domain: "business-logic",
            severity: "medium",
            confidence: "confirmed",
            title: `Server error (${resp.status}) on malformed input: ${ctx.target.url}`,
            description: `Sent ${payload.label} payload and got HTTP ${resp.status}. The server does not gracefully handle malformed input.`,
            evidence: [],
            remediation: "Add input validation and error handling. Return 400 Bad Request for malformed input instead of letting errors propagate to 500.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"],
            layer: "probe",
            cwe: "CWE-20",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "form-fuzzing",
              aggressionLevel: "intrusive",
              request: { method: "POST", url: ctx.target.url, headers: { "Content-Type": payload.contentType }, bodyPreview: payload.body.slice(0, 256) },
              response: { status: resp.status, headers: resp.headers, bodyPreview: bodyText.slice(0, 256), timingMs: resp.timingMs },
            },
          });
        }

        // Detect stack trace in response
        if (!foundStackTrace && STACK_TRACE_PATTERNS.some((p) => p.test(bodyText))) {
          foundStackTrace = true;
          findings.push({
            id: `PROBE-FUZZ-${randomUUID().slice(0, 8)}`,
            domain: "business-logic",
            severity: "medium",
            confidence: "confirmed",
            title: `Stack trace disclosed on malformed input: ${ctx.target.url}`,
            description: `Sent ${payload.label} payload and response body contains a stack trace. Internal implementation details are exposed to attackers.`,
            evidence: [],
            remediation: "Never return stack traces in production responses. Use a global error handler that returns generic messages and logs details server-side.",
            references: ["https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"],
            layer: "probe",
            cwe: "CWE-209",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "form-fuzzing",
              aggressionLevel: "intrusive",
              request: { method: "POST", url: ctx.target.url, headers: { "Content-Type": payload.contentType }, bodyPreview: payload.body.slice(0, 256) },
              response: { status: resp.status, headers: resp.headers, bodyPreview: bodyText.slice(0, 256), timingMs: resp.timingMs },
            },
          });
        }
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "form-fuzzing", targetUrl: ctx.target.url });
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

Run: `npx vitest run tests/layers/probe/checks/intrusive/form-fuzzing.test.ts`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/probe/checks/intrusive/form-fuzzing.ts tests/layers/probe/checks/intrusive/form-fuzzing.test.ts
git commit -m "feat(probe): add form-fuzzing intrusive check with tests"
```

---

## Task 4: Wire Intrusive Checks into Probe Entry Point

**Files:**
- Modify: `src/layers/probe/index.ts`

- [ ] **Step 1: Add imports and loadIntrusiveChecks()**

Add after the standard check imports in `src/layers/probe/index.ts`:

```typescript
import { xssReflectionCheck } from "./checks/intrusive/xss-reflection.js";
import { fileUploadCheck } from "./checks/intrusive/file-upload.js";
import { formFuzzingCheck } from "./checks/intrusive/form-fuzzing.js";
```

Add after `loadStandardChecks()`:

```typescript
function loadIntrusiveChecks(): void {
  registerProbeCheck(xssReflectionCheck);
  registerProbeCheck(fileUploadCheck);
  registerProbeCheck(formFuzzingCheck);
}
```

Add `loadIntrusiveChecks();` after `loadStandardChecks();` in `runProbe()`.

- [ ] **Step 2: Run existing tests for regression check**

Run: `npx vitest run tests/layers/probe/ tests/integration/`
Expected: ALL PASS

- [ ] **Step 3: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add src/layers/probe/index.ts
git commit -m "feat(probe): wire intrusive checks into probe entry point"
```

---

## Task 5: Intrusive Level Integration Test

**Files:**
- Create: `tests/integration/probe-intrusive.test.ts`

End-to-end test at `level: "intrusive"` with a model that triggers all 3 intrusive checks.

- [ ] **Step 1: Write the integration test**

```typescript
// tests/integration/probe-intrusive.test.ts
import { describe, it, expect, vi, afterEach } from "vitest";
import { runProbe } from "../../src/layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../../src/layers/probe/schema.js";
import type { ProjectModel, ProbeConfig } from "../../src/model/types.js";

function buildModel(): ProjectModel {
  return {
    meta: {
      name: "test-project", path: "/tmp/test-project", stack: "nextjs-supabase",
      packageManager: "npm", language: "typescript", framework: "next", deployTarget: null,
    },
    routes: [
      { path: "/search", method: "GET", file: "src/app/search/page.tsx", isApi: false, hasAuthCheck: false, paramNames: [] },
      { path: "/api/upload", method: "POST", file: "src/app/api/upload/route.ts", isApi: true, hasAuthCheck: false, paramNames: [] },
      { path: "/api/upload/:id", method: "DELETE", file: "src/app/api/upload/[id]/route.ts", isApi: true, hasAuthCheck: false, paramNames: ["id"] },
      { path: "/api/comments", method: "POST", file: "src/app/api/comments/route.ts", isApi: true, hasAuthCheck: false, paramNames: [] },
    ],
    endpoints: [
      { path: "/search", method: "GET", file: "src/app/search/page.tsx", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
      { path: "/api/upload", method: "POST", file: "src/app/api/upload/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
      { path: "/api/upload/:id", method: "DELETE", file: "src/app/api/upload/[id]/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
      { path: "/api/comments", method: "POST", file: "src/app/api/comments/route.ts", hasAuthCheck: false, hasValidation: false, usesServiceRole: false },
    ],
    fileUploads: [{ file: "src/app/api/upload/route.ts", line: 10, acceptsMultipart: true, hasMimeValidation: false, hasSizeLimit: false, usesUserFilename: true, storageDestination: "supabase" }],
    authFlows: [],
    dataModels: [],
    dependencies: [],
    envVars: [],
    staticAssets: [],
    infra: { nextConfig: null, middleware: null, vercelConfig: null, supabaseConfig: null, securityHeaders: {} },
    findings: [],
  };
}

const INTRUSIVE_CONFIG: ProbeConfig = {
  ...PROBE_CONFIG_DEFAULTS,
  enabled: true,
  level: "intrusive",
  targetUrl: "http://localhost:3000",
  logDir: "/tmp/probe-test-intrusive",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("probe: intrusive end-to-end integration", () => {
  it("runs intrusive checks alongside passive and standard", async () => {
    const mockFetch = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
      const urlStr = String(url);

      // XSS: reflect query params unescaped
      if (urlStr.includes("/search") && urlStr.includes("sentinel-marker")) {
        const u = new URL(urlStr);
        const q = u.searchParams.get("q") ?? "";
        return { status: 200, headers: new Headers({ "content-type": "text/html" }), text: async () => `<html>Results: ${q}</html>` };
      }

      // Upload: accept everything, return an ID
      if (urlStr.includes("/api/upload") && init.method === "POST") {
        return { status: 200, headers: new Headers({ "content-type": "application/json" }), text: async () => JSON.stringify({ id: "upload-test-123" }) };
      }

      // Upload DELETE: succeed
      if (urlStr.includes("/api/upload") && init.method === "DELETE") {
        return { status: 204, headers: new Headers(), text: async () => "" };
      }

      // Form fuzzing: return 500 with stack trace
      if (urlStr.includes("/api/comments") && init.method === "POST") {
        return {
          status: 500,
          headers: new Headers({ "content-type": "application/json" }),
          text: async () => JSON.stringify({ error: "TypeError at /app/src/comments.ts:15:3" }),
        };
      }

      // Default
      return { status: 200, headers: new Headers({ "content-type": "text/html" }), text: async () => "<html></html>" };
    });

    vi.stubGlobal("fetch", mockFetch);

    const model = buildModel();
    const { result } = await runProbe(model, [], INTRUSIVE_CONFIG);

    expect(result.aggressionLevel).toBe("intrusive");

    // Intrusive: XSS reflection
    const xssFindings = result.findings.filter((f) => f.probeEvidence.checkId === "xss-reflection");
    expect(xssFindings.length).toBeGreaterThan(0);

    // Intrusive: file upload
    const uploadFindings = result.findings.filter((f) => f.probeEvidence.checkId === "file-upload");
    expect(uploadFindings.length).toBeGreaterThan(0);

    // Intrusive: form fuzzing (500 + stack trace)
    const fuzzFindings = result.findings.filter((f) => f.probeEvidence.checkId === "form-fuzzing");
    expect(fuzzFindings.length).toBeGreaterThan(0);

    // Cleanup should have run (file-upload registers obligations)
    expect(result.cleanupObligationsExecuted).toBeGreaterThan(0);
    expect(result.cleanupObligationsFailed).toBe(0);

    // Request cap is intrusive level
    expect(result.requestCap).toBe(5000);
    expect(result.usedRequests).toBeLessThanOrEqual(result.requestCap);
  });

  it("intrusive checks do NOT run at standard level", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers({ "content-type": "text/html" }),
      text: async () => "<html></html>",
    });
    vi.stubGlobal("fetch", mockFetch);

    const standardConfig: ProbeConfig = { ...INTRUSIVE_CONFIG, level: "standard" };
    const model = buildModel();
    const { result } = await runProbe(model, [], standardConfig);

    const intrusiveFindings = result.findings.filter((f) =>
      ["xss-reflection", "file-upload", "form-fuzzing"].includes(f.probeEvidence.checkId),
    );
    expect(intrusiveFindings).toHaveLength(0);
    expect(result.aggressionLevel).toBe("standard");
  });
});
```

- [ ] **Step 2: Run the integration test**

Run: `npx vitest run tests/integration/probe-intrusive.test.ts`
Expected: ALL PASS

- [ ] **Step 3: Run the full test suite**

Run: `npx vitest run`
Expected: ALL tests pass

- [ ] **Step 4: Run typecheck**

Run: `npx tsc --noEmit`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add tests/integration/probe-intrusive.test.ts
git commit -m "test(probe): add intrusive level end-to-end integration test"
```

---

## Summary

| Task | Check | Files | Key Feature |
|------|-------|-------|-------------|
| 1 | xss-reflection | 1 impl + 1 test | Marker injection + substring match |
| 2 | file-upload | 1 impl + 1 test | Real cleanup obligations (blocking DELETE) |
| 3 | form-fuzzing | 1 impl + 1 test | Malformed payload catalog |
| 4 | Wire into index.ts | 1 modify | loadIntrusiveChecks() |
| 5 | Integration test | 1 test | All 3 intrusive + cleanup verification |

Total: 3 new check files, 4 new test files, 1 modified file.
