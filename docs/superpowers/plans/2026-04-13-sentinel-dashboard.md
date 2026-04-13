# Sentinel Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--dashboard` flag to `sentinel scan` that opens a real-time D3.js visualization of the attack surface in the browser, streaming findings via WebSocket as the scan runs, then transitioning to interactive exploration mode.

**Architecture:** Three new modules: (1) a typed event emitter that wraps the scan orchestrator, (2) an Express+WebSocket server that forwards events, (3) a static D3.js client that renders hybrid lane graphs. The emitter is threaded through existing layer functions via an optional parameter so the zero-dashboard path is unchanged.

**Tech Stack:** TypeScript, Express, ws (WebSocket), D3.js v7 (CDN), open (browser launch)

**Spec:** `docs/superpowers/specs/2026-04-13-dashboard-design.md`

---

## File Structure

```
src/dashboard/
  events.ts          # ScanEventEmitter class, ScanEvent union type, all data interfaces
  server.ts          # Express static server + WebSocket relay + browser open
  client/
    index.html       # Dashboard HTML shell (loads D3 from CDN, links app.js + styles.css)
    styles.css       # Dark theme, lane layout, sidebar, animations
    app.js           # WebSocket subscription, state management, mode switching
    graph.js         # D3 force simulation: lanes, nodes, edges, animations
    sidebar.js       # Stats panel, activity log, node detail panel

src/commands/scan.ts       # Modified: accept emitter, pass to layers
src/layers/recon/index.ts  # Modified: accept optional emitter, emit recon events
src/layers/rules/index.ts  # Modified: accept optional emitter, emit finding events
src/layers/ai/index.ts     # Modified: accept optional emitter, emit finding events
src/cli.ts                 # Modified: add --dashboard and --port flags

tests/dashboard/
  events.test.ts     # ScanEventEmitter unit tests
  server.test.ts     # Server startup/shutdown, WebSocket relay tests
```

### Dependency between tasks

```
Task 1 (events.ts)
  ├── Task 2 (server.ts)           ← needs emitter
  ├── Task 3 (instrument scan.ts)  ← needs emitter
  │     ├── Task 4 (instrument recon)
  │     ├── Task 5 (instrument rules)
  │     └── Task 6 (instrument AI)
  └── Task 7 (CLI flags)           ← needs server + emitter
Task 8 (client/index.html + styles.css)
Task 9 (client/app.js)             ← needs event types from Task 1
Task 10 (client/graph.js)          ← needs app.js state
Task 11 (client/sidebar.js)        ← needs app.js state
Task 12 (integration test)         ← needs everything
```

Tasks 1-7 are backend (TypeScript). Tasks 8-11 are frontend (vanilla JS). Task 12 is integration.

---

### Task 1: Event System (`src/dashboard/events.ts`)

**Files:**
- Create: `src/dashboard/events.ts`
- Create: `tests/dashboard/events.test.ts`

This is the foundation. Every other task depends on the event types defined here.

- [ ] **Step 1: Write the failing test for ScanEventEmitter**

```typescript
// tests/dashboard/events.test.ts
import { describe, it, expect, vi } from "vitest";
import { ScanEventEmitter } from "../../src/dashboard/events.js";
import type { ScanEvent } from "../../src/dashboard/events.js";

describe("ScanEventEmitter", () => {
  it("emits scan:start event with correct shape", () => {
    const emitter = new ScanEventEmitter();
    const handler = vi.fn();
    emitter.on("scan-event", handler);

    emitter.emitEvent({ type: "scan:start", project: "test-project", timestamp: Date.now() });

    expect(handler).toHaveBeenCalledOnce();
    const event: ScanEvent = handler.mock.calls[0][0];
    expect(event.type).toBe("scan:start");
    expect(event.project).toBe("test-project");
  });

  it("emits recon:route event with route data", () => {
    const emitter = new ScanEventEmitter();
    const handler = vi.fn();
    emitter.on("scan-event", handler);

    emitter.emitEvent({
      type: "recon:route",
      data: { path: "/api/users", method: "GET", file: "src/app/api/users/route.ts", isApi: true, hasAuthCheck: true },
    });

    const event = handler.mock.calls[0][0] as ScanEvent;
    expect(event.type).toBe("recon:route");
    if (event.type === "recon:route") {
      expect(event.data.path).toBe("/api/users");
      expect(event.data.isApi).toBe(true);
    }
  });

  it("emits finding event", () => {
    const emitter = new ScanEventEmitter();
    const handler = vi.fn();
    emitter.on("scan-event", handler);

    emitter.emitEvent({
      type: "finding",
      data: {
        id: "RULE-001",
        severity: "high",
        title: "Exposed API key",
        file: "src/config.ts",
        line: 42,
        domain: "secrets-exposure",
        layer: "rules",
      },
    });

    const event = handler.mock.calls[0][0] as ScanEvent;
    expect(event.type).toBe("finding");
    if (event.type === "finding") {
      expect(event.data.severity).toBe("high");
    }
  });

  it("emits layer lifecycle events", () => {
    const emitter = new ScanEventEmitter();
    const events: ScanEvent[] = [];
    emitter.on("scan-event", (e) => events.push(e));

    emitter.emitEvent({ type: "layer:start", layer: "recon", timestamp: Date.now() });
    emitter.emitEvent({ type: "layer:complete", layer: "recon", durationMs: 1200, timestamp: Date.now() });

    expect(events).toHaveLength(2);
    expect(events[0].type).toBe("layer:start");
    expect(events[1].type).toBe("layer:complete");
  });

  it("emits scan:complete with summary", () => {
    const emitter = new ScanEventEmitter();
    const handler = vi.fn();
    emitter.on("scan-event", handler);

    emitter.emitEvent({
      type: "scan:complete",
      summary: {
        routes: 12,
        endpoints: 8,
        dataModels: 3,
        externalServices: 2,
        findings: { critical: 1, high: 3, medium: 5, low: 2, info: 0 },
        durationMs: 4500,
      },
      timestamp: Date.now(),
    });

    const event = handler.mock.calls[0][0] as ScanEvent;
    expect(event.type).toBe("scan:complete");
    if (event.type === "scan:complete") {
      expect(event.summary.routes).toBe(12);
      expect(event.summary.findings.critical).toBe(1);
    }
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx vitest run tests/dashboard/events.test.ts`
Expected: FAIL with "Cannot find module" (events.ts doesn't exist yet)

- [ ] **Step 3: Implement ScanEventEmitter and all event types**

```typescript
// src/dashboard/events.ts
import { EventEmitter } from "node:events";
import type { Severity, SecurityDomain, Layer } from "../model/types.js";

// ── Lane assignment ──────────────────────────────────────────────────────────

export type LaneName = "frontend" | "api" | "database" | "external";

// ── Data shapes for recon events ─────────────────────────────────────────────

export interface RouteEventData {
  path: string;
  method: string;
  file: string;
  isApi: boolean;
  hasAuthCheck: boolean;
}

export interface EndpointEventData {
  path: string;
  method: string;
  file: string;
  hasValidation: boolean;
  hasAuthCheck: boolean;
  usesServiceRole: boolean;
}

export interface DataModelEventData {
  name: string;
  file: string;
  hasRLS: boolean;
  policies: string[];
}

export interface AuthFlowEventData {
  type: string;
  file: string;
  provider?: string;
}

export interface EnvVarEventData {
  name: string;
  clientExposed: boolean;
  referencedIn: string[];
}

export interface ExternalServiceEventData {
  name: string;
  type: "api" | "storage" | "webhook" | "automation";
  file: string;
}

// ── Finding event data (subset for dashboard) ───────────────────────────────

export interface FindingEventData {
  id: string;
  severity: Severity;
  title: string;
  description?: string;
  file: string;
  line?: number;
  domain: SecurityDomain;
  layer: Layer;
  remediation?: string;
}

// ── Edge event data ──────────────────────────────────────────────────────────

export interface EdgeEventData {
  source: string;
  target: string;
  type: "calls" | "queries" | "uses" | "exposes";
}

// ── Scan summary ─────────────────────────────────────────────────────────────

export interface ScanSummary {
  routes: number;
  endpoints: number;
  dataModels: number;
  externalServices: number;
  findings: Record<Severity, number>;
  durationMs: number;
}

// ── Layer name ───────────────────────────────────────────────────────────────

export type LayerName = "recon" | "rules" | "probe" | "ai";

// ── Event union ──────────────────────────────────────────────────────────────

export type ScanEvent =
  | { type: "scan:start"; project: string; timestamp: number }
  | { type: "scan:complete"; summary: ScanSummary; timestamp: number }
  | { type: "layer:start"; layer: LayerName; timestamp: number }
  | { type: "layer:complete"; layer: LayerName; durationMs: number; timestamp: number }
  | { type: "recon:route"; data: RouteEventData }
  | { type: "recon:endpoint"; data: EndpointEventData }
  | { type: "recon:datamodel"; data: DataModelEventData }
  | { type: "recon:authflow"; data: AuthFlowEventData }
  | { type: "recon:envvar"; data: EnvVarEventData }
  | { type: "recon:external"; data: ExternalServiceEventData }
  | { type: "finding"; data: FindingEventData }
  | { type: "edge"; data: EdgeEventData }
  | { type: "log"; message: string; level: "info" | "warn" | "error" };

// ── Emitter class ────────────────────────────────────────────────────────────

export class ScanEventEmitter extends EventEmitter {
  emitEvent(event: ScanEvent): void {
    this.emit("scan-event", event);
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx vitest run tests/dashboard/events.test.ts`
Expected: PASS (5 tests)

- [ ] **Step 5: Run typecheck**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 6: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/dashboard/events.ts tests/dashboard/events.test.ts
git commit -m "feat(dashboard): add ScanEventEmitter and typed event system"
```

---

### Task 2: Dashboard Server (`src/dashboard/server.ts`)

**Files:**
- Create: `src/dashboard/server.ts`
- Create: `tests/dashboard/server.test.ts`

**Dependencies:** Task 1 (imports ScanEventEmitter)

**New packages needed:** `express`, `ws`, `open`, and their type declarations.

- [ ] **Step 1: Install dependencies**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
npm install express ws open
npm install -D @types/express @types/ws
```

- [ ] **Step 2: Write the failing test for DashboardServer**

```typescript
// tests/dashboard/server.test.ts
import { describe, it, expect, afterEach } from "vitest";
import { ScanEventEmitter } from "../../src/dashboard/events.js";
import { startDashboard, type DashboardHandle } from "../../src/dashboard/server.js";
import WebSocket from "ws";

describe("DashboardServer", () => {
  let handle: DashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.close();
      handle = null;
    }
  });

  it("starts on the specified port and serves index.html", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });

    const res = await fetch(`http://localhost:${handle.port}/`);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain("Sentinel Dashboard");
  });

  it("relays scan events to WebSocket clients", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });

    const ws = new WebSocket(`ws://localhost:${handle.port}/ws`);
    const messages: string[] = [];

    await new Promise<void>((resolve) => {
      ws.on("open", () => resolve());
    });

    ws.on("message", (data) => messages.push(data.toString()));

    emitter.emitEvent({ type: "scan:start", project: "test", timestamp: Date.now() });

    // Give the event loop a tick to deliver
    await new Promise((r) => setTimeout(r, 50));

    expect(messages).toHaveLength(1);
    const parsed = JSON.parse(messages[0]);
    expect(parsed.type).toBe("scan:start");
    expect(parsed.project).toBe("test");

    ws.close();
  });

  it("closes cleanly", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });
    const port = handle.port;

    await handle.close();
    handle = null;

    // Port should be released
    await expect(fetch(`http://localhost:${port}/`)).rejects.toThrow();
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx vitest run tests/dashboard/server.test.ts`
Expected: FAIL with "Cannot find module" (server.ts doesn't exist)

- [ ] **Step 4: Implement the dashboard server**

```typescript
// src/dashboard/server.ts
import express from "express";
import { WebSocketServer } from "ws";
import { createServer, type Server } from "node:http";
import open from "open";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { ScanEventEmitter } from "./events.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

export interface DashboardOptions {
  port?: number;        // default: 4400
  openBrowser?: boolean; // default: true
}

export interface DashboardHandle {
  port: number;
  close: () => Promise<void>;
}

export async function startDashboard(
  emitter: ScanEventEmitter,
  options?: DashboardOptions,
): Promise<DashboardHandle> {
  const port = options?.port ?? 4400;
  const app = express();
  const server = createServer(app);
  const wss = new WebSocketServer({ server, path: "/ws" });

  // Serve static client files
  app.use(express.static(join(__dirname, "client")));

  // Forward scan events to all connected WebSocket clients
  emitter.on("scan-event", (event) => {
    const payload = JSON.stringify(event);
    for (const client of wss.clients) {
      if (client.readyState === 1) {
        client.send(payload);
      }
    }
  });

  const actualPort = await new Promise<number>((resolve, reject) => {
    server.on("error", reject);
    server.listen(port, () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        resolve(addr.port);
      } else {
        resolve(port);
      }
    });
  });

  if (options?.openBrowser !== false) {
    await open(`http://localhost:${actualPort}`);
  }

  return {
    port: actualPort,
    close: () =>
      new Promise<void>((resolve, reject) => {
        // Close all WebSocket connections first
        for (const client of wss.clients) {
          client.terminate();
        }
        wss.close(() => {
          server.close((err) => (err ? reject(err) : resolve()));
        });
      }),
  };
}
```

- [ ] **Step 5: Create a minimal placeholder `client/index.html` so the static serve test passes**

```html
<!-- src/dashboard/client/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel Dashboard</title>
</head>
<body>
  <h1>Sentinel Dashboard</h1>
  <p>Placeholder - will be replaced in Task 8.</p>
</body>
</html>
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx vitest run tests/dashboard/server.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 7: Run typecheck**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsc --noEmit`
Expected: No errors

- [ ] **Step 8: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/dashboard/server.ts src/dashboard/client/index.html tests/dashboard/server.test.ts package.json package-lock.json
git commit -m "feat(dashboard): add Express+WebSocket server with relay"
```

---

### Task 3: Instrument Scan Orchestrator (`src/commands/scan.ts`)

**Files:**
- Modify: `src/commands/scan.ts`

**Dependencies:** Task 1

The scan orchestrator needs to: (1) accept an optional `ScanEventEmitter`, (2) emit `scan:start`, `layer:start`/`layer:complete`, and `scan:complete` events, (3) pass the emitter to each layer. This task only wires the orchestrator. Tasks 4-6 instrument the individual layers.

- [ ] **Step 1: Add emitter to ScanOptions and import**

Add to the `ScanOptions` interface in `src/commands/scan.ts`:

```typescript
import { ScanEventEmitter } from "../dashboard/events.js";
import type { ScanEvent, ScanSummary } from "../dashboard/events.js";
```

Add to the `ScanOptions` interface:

```typescript
export interface ScanOptions {
  // ... existing fields ...
  dashboard?: boolean;
  dashboardPort?: number;
  emitter?: ScanEventEmitter; // injected for testing; created internally when dashboard=true
}
```

- [ ] **Step 2: Emit lifecycle events around each phase in `runScan`**

Modify `runScan` to create an emitter when `dashboard` is true, and emit lifecycle events. Wrap each layer call:

After `const config = await loadConfig(options.path);`:
```typescript
  const emitter = options.emitter ?? (options.dashboard ? new ScanEventEmitter() : null);

  // Start dashboard server if requested
  let dashboardHandle: import("../dashboard/server.js").DashboardHandle | null = null;
  if (options.dashboard && emitter) {
    const { startDashboard } = await import("../dashboard/server.js");
    dashboardHandle = await startDashboard(emitter, {
      port: options.dashboardPort,
      openBrowser: true,
    });
    process.stderr.write(`Dashboard: http://localhost:${dashboardHandle.port}\n`);
  }

  emitter?.emitEvent({ type: "scan:start", project: options.path, timestamp: Date.now() });
```

Wrap recon:
```typescript
  emitter?.emitEvent({ type: "layer:start", layer: "recon", timestamp: Date.now() });
  const reconStart = Date.now();
  const model = await runRecon(options.path, config.exclude, emitter ?? undefined);
  const recon_ms = Date.now() - reconStart;
  emitter?.emitEvent({ type: "layer:complete", layer: "recon", durationMs: recon_ms, timestamp: Date.now() });
```

Wrap rules:
```typescript
  emitter?.emitEvent({ type: "layer:start", layer: "rules", timestamp: Date.now() });
  const rulesStart = Date.now();
  const ruleFindings = await runRules(model, context, emitter ?? undefined);
  const rules_ms = Date.now() - rulesStart;
  emitter?.emitEvent({ type: "layer:complete", layer: "rules", durationMs: rules_ms, timestamp: Date.now() });
```

Wrap AI (inside `if (aiConfig.enabled)`):
```typescript
    emitter?.emitEvent({ type: "layer:start", layer: "ai", timestamp: Date.now() });
    const aiStart = Date.now();
    try {
      aiResult = await runAI(model, aiConfig, undefined, emitter ?? undefined);
    } catch (err) {
      // ... existing error handling ...
    }
    ai_ms = Date.now() - aiStart;
    emitter?.emitEvent({ type: "layer:complete", layer: "ai", durationMs: ai_ms, timestamp: Date.now() });
```

After output, emit `scan:complete`:
```typescript
  if (emitter) {
    const summary: ScanSummary = {
      routes: model.routes.length,
      endpoints: model.endpoints.length,
      dataModels: model.dataModels.length,
      externalServices: 0,
      findings: {
        critical: allFindings.filter((f) => f.severity === "critical").length,
        high: allFindings.filter((f) => f.severity === "high").length,
        medium: allFindings.filter((f) => f.severity === "medium").length,
        low: allFindings.filter((f) => f.severity === "low").length,
        info: allFindings.filter((f) => f.severity === "info").length,
      },
      durationMs: recon_ms + rules_ms + ai_ms,
    };
    emitter.emitEvent({ type: "scan:complete", summary, timestamp: Date.now() });
  }
```

At the end, if dashboard is running, keep the process alive:
```typescript
  if (dashboardHandle) {
    process.stderr.write("Dashboard running. Press Ctrl+C to exit.\n");
    await new Promise<void>((resolve) => {
      process.on("SIGINT", async () => {
        await dashboardHandle!.close();
        resolve();
      });
    });
  }

  return hasBlockingFinding ? 1 : 0;
```

- [ ] **Step 3: Run typecheck**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsc --noEmit`
Expected: Errors about `runRecon`, `runRules`, `runAI` not accepting emitter parameter yet. That's correct. These get fixed in Tasks 4-6.

- [ ] **Step 4: Commit (work in progress)**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/commands/scan.ts
git commit -m "feat(dashboard): wire emitter into scan orchestrator (WIP - layers not yet instrumented)"
```

---

### Task 4: Instrument Recon Layer

**Files:**
- Modify: `src/layers/recon/index.ts`

**Dependencies:** Task 1, Task 3

- [ ] **Step 1: Add optional emitter parameter to `runRecon`**

```typescript
// src/layers/recon/index.ts
import type { ScanEventEmitter } from "../../dashboard/events.js";

export async function runRecon(
  projectPath: string,
  exclude: string[],
  emitter?: ScanEventEmitter,
): Promise<ProjectModel> {
  const meta = await detectStack(projectPath);
  const files = await walkProject(projectPath, exclude);

  const [routes, authFlows, fileUploads, envVars, dependencies, infra] = await Promise.all([
    discoverRoutes(projectPath, meta.framework),
    discoverAuthFlows(files),
    discoverUploadHandlers(files),
    discoverEnvVars(projectPath, files),
    discoverDependencies(projectPath),
    discoverInfra(projectPath),
  ]);

  const endpoints = await discoverEndpoints(routes);

  // Emit recon events if dashboard is active
  if (emitter) {
    for (const r of routes) {
      emitter.emitEvent({
        type: r.isApi ? "recon:endpoint" : "recon:route",
        data: r.isApi
          ? {
              path: r.path,
              method: r.method,
              file: r.file,
              hasValidation: false,
              hasAuthCheck: r.hasAuthCheck,
              usesServiceRole: false,
            }
          : {
              path: r.path,
              method: r.method,
              file: r.file,
              isApi: r.isApi,
              hasAuthCheck: r.hasAuthCheck,
            },
      });
    }

    for (const ep of endpoints) {
      emitter.emitEvent({
        type: "recon:endpoint",
        data: {
          path: ep.path,
          method: ep.method,
          file: ep.file,
          hasValidation: ep.hasValidation,
          hasAuthCheck: ep.hasAuthCheck,
          usesServiceRole: ep.usesServiceRole,
        },
      });
    }

    for (const af of authFlows) {
      emitter.emitEvent({
        type: "recon:authflow",
        data: { type: af.type, file: af.file, provider: af.provider },
      });
    }

    for (const ev of envVars) {
      emitter.emitEvent({
        type: "recon:envvar",
        data: { name: ev.name, clientExposed: ev.clientExposed, referencedIn: ev.referencedIn },
      });
    }

    // Emit edges: routes that map to API endpoints
    for (const route of routes.filter((r) => r.isApi)) {
      const matching = endpoints.find((ep) => ep.path === route.path && ep.method === route.method);
      if (matching) {
        emitter.emitEvent({
          type: "edge",
          data: { source: route.path, target: matching.path, type: "calls" },
        });
      }
    }
  }

  return {
    meta,
    routes,
    endpoints,
    fileUploads,
    authFlows,
    dataModels: [],
    dependencies,
    envVars,
    staticAssets: [],
    infra,
    findings: [],
  };
}
```

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsc --noEmit`
Expected: Still errors from rules/AI not accepting emitter (Tasks 5-6 fix those). No new errors from recon.

- [ ] **Step 3: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/layers/recon/index.ts
git commit -m "feat(dashboard): instrument recon layer with event emission"
```

---

### Task 5: Instrument Rules Layer

**Files:**
- Modify: `src/layers/rules/index.ts`

**Dependencies:** Task 1

- [ ] **Step 1: Add optional emitter parameter to `runRules`**

```typescript
// src/layers/rules/index.ts
import type { ScanEventEmitter } from "../../dashboard/events.js";

export async function runRules(
  model: ProjectModel,
  context?: ProjectContext | null,
  emitter?: ScanEventEmitter,
): Promise<Finding[]> {
  const rules = getRules().filter((r) => r.appliesTo.includes(model.meta.stack));
  const results = await Promise.all(rules.map((r) => Promise.resolve(r.check(model, context))));
  const findings = results.flat();

  if (emitter) {
    for (const f of findings) {
      emitter.emitEvent({
        type: "finding",
        data: {
          id: f.id,
          severity: f.severity,
          title: f.title,
          description: f.description,
          file: f.evidence[0]?.file ?? "",
          line: f.evidence[0]?.line,
          domain: f.domain,
          layer: f.layer,
          remediation: f.remediation,
        },
      });
    }
  }

  return findings;
}
```

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsc --noEmit`
Expected: Still error from AI layer. Rules and recon should be clean now.

- [ ] **Step 3: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/layers/rules/index.ts
git commit -m "feat(dashboard): instrument rules layer with finding emission"
```

---

### Task 6: Instrument AI Layer

**Files:**
- Modify: `src/layers/ai/index.ts`

**Dependencies:** Task 1

- [ ] **Step 1: Add optional emitter parameter to `runAI`**

```typescript
// src/layers/ai/index.ts — update the runAI signature:

export async function runAI(
  model: ProjectModel,
  config: AIConfig,
  injectedProvider?: AIProvider,
  emitter?: ScanEventEmitter,
): Promise<AIRunResult> {
  // ... existing implementation unchanged ...
  // After dedup and magic-link cap, emit findings:
  if (emitter) {
    for (const f of result.findings) {
      emitter.emitEvent({
        type: "finding",
        data: {
          id: f.id,
          severity: f.severity,
          title: f.title,
          description: f.description,
          file: f.evidence[0]?.file ?? "",
          line: f.evidence[0]?.line,
          domain: f.domain,
          layer: f.layer,
          remediation: f.remediation,
        },
      });
    }
  }
  return result;
}
```

Add the import at the top:
```typescript
import type { ScanEventEmitter } from "../../dashboard/events.js";
```

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsc --noEmit`
Expected: PASS (all layers now accept the optional emitter)

- [ ] **Step 3: Run all existing tests**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx vitest run`
Expected: All tests pass (no behavioral change when emitter is not provided)

- [ ] **Step 4: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/layers/ai/index.ts
git commit -m "feat(dashboard): instrument AI layer with finding emission"
```

---

### Task 7: CLI Flags (`--dashboard`, `--port`)

**Files:**
- Modify: `src/cli.ts`

**Dependencies:** Tasks 3-6

- [ ] **Step 1: Add CLI flags to the scan command**

In `src/cli.ts`, add to the `.command("scan")` chain, before `.action(...)`:

```typescript
  .option("--dashboard", "Open real-time attack surface visualization in browser")
  .option("--port <number>", "Dashboard server port (default: 4400)", parseInt)
```

In the `.action` handler, add to the options object passed to `runScan`:

```typescript
    const exitCode = await runScan({
      // ... existing fields ...
      dashboard: !!options.dashboard,
      dashboardPort: options.port,
    });
```

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsc --noEmit`
Expected: PASS

- [ ] **Step 3: Verify help text**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsx src/cli.ts scan --help`
Expected: Output includes `--dashboard` and `--port <number>` options.

- [ ] **Step 4: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/cli.ts
git commit -m "feat(dashboard): add --dashboard and --port CLI flags"
```

---

### Task 8: Dashboard HTML Shell + Styles

**Files:**
- Replace: `src/dashboard/client/index.html`
- Create: `src/dashboard/client/styles.css`

**Dependencies:** None (static files)

- [ ] **Step 1: Write the HTML shell**

```html
<!-- src/dashboard/client/index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentinel Dashboard</title>
  <link rel="stylesheet" href="styles.css">
  <script src="https://d3js.org/d3.v7.min.js"></script>
</head>
<body>
  <!-- Top Bar -->
  <header id="top-bar">
    <div class="top-bar-left">
      <span class="logo">SENTINEL</span>
      <span id="scan-status" class="status scanning">
        <span class="status-dot"></span>
        <span id="scan-status-text">Connecting...</span>
      </span>
    </div>
    <div id="severity-filters" class="top-bar-right hidden">
      <button class="filter-btn active" data-severity="all">All</button>
      <button class="filter-btn" data-severity="critical">Critical</button>
      <button class="filter-btn" data-severity="high">High</button>
      <button class="filter-btn" data-severity="medium">Medium</button>
    </div>
  </header>

  <!-- Main Content -->
  <main>
    <!-- Graph Area (lanes) -->
    <div id="graph-area">
      <svg id="graph-svg">
        <!-- Lane backgrounds and nodes rendered by D3 -->
      </svg>
      <!-- Lane headers overlay -->
      <div id="lane-headers">
        <div class="lane-header" data-lane="frontend">
          <span class="lane-name">FRONTEND</span>
          <span class="lane-status" id="lane-status-frontend">pending</span>
        </div>
        <div class="lane-header" data-lane="api">
          <span class="lane-name">API</span>
          <span class="lane-status" id="lane-status-api">pending</span>
        </div>
        <div class="lane-header" data-lane="database">
          <span class="lane-name">DATABASE</span>
          <span class="lane-status" id="lane-status-database">pending</span>
        </div>
        <div class="lane-header" data-lane="external">
          <span class="lane-name">EXTERNAL</span>
          <span class="lane-status" id="lane-status-external">pending</span>
        </div>
      </div>
    </div>

    <!-- Right Sidebar -->
    <aside id="sidebar">
      <!-- Scan Mode: Stats + Log -->
      <div id="sidebar-scan" class="sidebar-content">
        <div id="stats-panel" class="panel">
          <h3>Scan Stats</h3>
          <div class="stat-row"><span class="stat-label">Routes</span><span id="stat-routes" class="stat-value">0</span></div>
          <div class="stat-row"><span class="stat-label">Endpoints</span><span id="stat-endpoints" class="stat-value">0</span></div>
          <div class="stat-row"><span class="stat-label">Findings</span><span id="stat-findings" class="stat-value">0</span></div>
          <div class="stat-row severity-row"><span class="stat-label critical-label">Critical</span><span id="stat-critical" class="stat-value">0</span></div>
          <div class="stat-row severity-row"><span class="stat-label high-label">High</span><span id="stat-high" class="stat-value">0</span></div>
          <div class="stat-row severity-row"><span class="stat-label medium-label">Medium</span><span id="stat-medium" class="stat-value">0</span></div>
          <div class="stat-row severity-row"><span class="stat-label low-label">Low</span><span id="stat-low" class="stat-value">0</span></div>
        </div>
        <div id="activity-log" class="panel">
          <h3>Activity</h3>
          <div id="log-entries"></div>
        </div>
      </div>

      <!-- Exploration Mode: Node Detail + Findings -->
      <div id="sidebar-explore" class="sidebar-content hidden">
        <div id="node-detail" class="panel">
          <h3 id="node-detail-title">Select a node</h3>
          <div id="node-detail-body">
            <p class="muted">Click a node in the graph to see details.</p>
          </div>
        </div>
        <div id="node-findings" class="panel">
          <h3>Findings</h3>
          <div id="node-findings-list"></div>
        </div>
      </div>
    </aside>
  </main>

  <script src="graph.js"></script>
  <script src="sidebar.js"></script>
  <script src="app.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write the CSS (dark theme, lane layout, sidebar, animations)**

```css
/* src/dashboard/client/styles.css */

/* ── Reset & Base ─────────────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg-deep:    #0a1628;
  --bg-panel:   #0d1f33;
  --bg-lane:    #0d2137;
  --border:     #1e3a5f;
  --text:       #e2e8f0;
  --text-sec:   #94a3b8;
  --text-muted: #64748b;

  --node-fill:       #0f4c75;
  --node-border:     #7bb3e0;
  --db-fill:         #14532d;
  --db-border:       #4ade80;
  --ext-fill:        #4a1d96;
  --ext-border:      #a78bfa;

  --critical-fill:   #991b1b;
  --critical-border: #ef4444;
  --critical-glow:   rgba(239,68,68,0.4);
  --high-fill:       #7c2d12;
  --high-border:     #f97316;
  --high-glow:       rgba(249,115,22,0.3);
  --medium-fill:     #78350f;
  --medium-border:   #f59e0b;
  --medium-glow:     rgba(245,158,11,0.2);

  --edge-color:      rgba(45,90,142,0.5);
  --selected-border: #fbbf24;
  --selected-glow:   rgba(251,191,36,0.4);

  --sidebar-width:   320px;
  --topbar-height:   48px;
}

body {
  font-family: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg-deep);
  color: var(--text);
  height: 100vh;
  overflow: hidden;
}

/* ── Top Bar ──────────────────────────────────────────────────────────────── */
#top-bar {
  height: var(--topbar-height);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border);
}

.top-bar-left { display: flex; align-items: center; gap: 16px; }
.logo { font-weight: 700; font-size: 14px; letter-spacing: 2px; color: var(--text); }

.status { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-sec); }
.status-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--text-muted);
}
.status.scanning .status-dot {
  background: #f59e0b;
  animation: pulse-dot 1.5s ease-in-out infinite;
}
.status.complete .status-dot { background: #22c55e; }

@keyframes pulse-dot {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.top-bar-right { display: flex; gap: 4px; }

.filter-btn {
  padding: 4px 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: transparent;
  color: var(--text-sec);
  font-size: 12px;
  cursor: pointer;
  transition: all 0.15s;
}
.filter-btn:hover { border-color: var(--text-sec); color: var(--text); }
.filter-btn.active { background: var(--border); color: var(--text); }

/* ── Main Layout ──────────────────────────────────────────────────────────── */
main {
  display: flex;
  height: calc(100vh - var(--topbar-height));
}

#graph-area {
  flex: 1;
  position: relative;
  overflow: hidden;
}

#graph-svg {
  width: 100%;
  height: 100%;
}

/* ── Lane Headers ─────────────────────────────────────────────────────────── */
#lane-headers {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  display: flex;
  pointer-events: none;
}

.lane-header {
  flex: 1;
  padding: 8px 12px;
  font-size: 11px;
  letter-spacing: 1.5px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
  border-bottom: 2px solid transparent;
}

.lane-header[data-state="scanning"] {
  border-bottom-color: #f59e0b;
}
.lane-header[data-state="complete"] {
  border-bottom-color: #22c55e;
}
.lane-header[data-state="issues"] {
  border-bottom-color: var(--critical-border);
}

.lane-name { color: var(--text-sec); }
.lane-status { color: var(--text-muted); font-weight: 400; letter-spacing: 0; }

/* Pending lanes dim */
.lane-header[data-state="pending"] { opacity: 0.5; }

/* ── Sidebar ──────────────────────────────────────────────────────────────── */
#sidebar {
  width: var(--sidebar-width);
  background: var(--bg-panel);
  border-left: 1px solid var(--border);
  overflow-y: auto;
}

.sidebar-content { display: flex; flex-direction: column; height: 100%; }
.sidebar-content.hidden { display: none; }

.panel {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
.panel h3 {
  font-size: 12px;
  letter-spacing: 1px;
  color: var(--text-sec);
  margin-bottom: 10px;
  text-transform: uppercase;
}

/* Stats */
.stat-row {
  display: flex;
  justify-content: space-between;
  padding: 3px 0;
  font-size: 13px;
}
.stat-label { color: var(--text-sec); }
.stat-value { color: var(--text); font-variant-numeric: tabular-nums; }
.severity-row { padding-left: 12px; }
.critical-label { color: var(--critical-border); }
.high-label { color: var(--high-border); }
.medium-label { color: var(--medium-border); }
.low-label { color: var(--text-sec); }

/* Activity Log */
#activity-log { flex: 1; overflow-y: auto; }
#log-entries { font-size: 12px; font-family: "JetBrains Mono", "Fira Code", monospace; }
.log-entry {
  padding: 3px 0;
  color: var(--text-muted);
  border-bottom: 1px solid rgba(30,58,95,0.3);
}
.log-entry .log-time { color: var(--text-muted); margin-right: 8px; }
.log-entry.warn { color: var(--medium-border); }
.log-entry.error { color: var(--critical-border); }

/* Node Detail */
#node-detail-body { font-size: 13px; }
.muted { color: var(--text-muted); font-style: italic; }
.detail-field { margin-bottom: 6px; }
.detail-label { color: var(--text-sec); font-size: 11px; text-transform: uppercase; }
.detail-value { color: var(--text); }
.detail-tag {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 11px;
  margin-right: 4px;
}
.detail-tag.auth { background: #14532d; color: #4ade80; }
.detail-tag.no-auth { background: var(--critical-fill); color: var(--critical-border); }
.detail-tag.validated { background: #1e3a5f; color: var(--node-border); }

/* Findings List */
.finding-card {
  padding: 8px;
  margin-bottom: 6px;
  border-radius: 4px;
  background: var(--bg-deep);
  border-left: 3px solid var(--text-muted);
}
.finding-card.critical { border-left-color: var(--critical-border); }
.finding-card.high { border-left-color: var(--high-border); }
.finding-card.medium { border-left-color: var(--medium-border); }
.finding-card .finding-title { font-size: 13px; font-weight: 500; margin-bottom: 4px; }
.finding-card .finding-location { font-size: 11px; color: var(--text-muted); }
.finding-card .finding-remediation { font-size: 12px; color: var(--text-sec); margin-top: 4px; }

/* ── Severity Badge (on nodes) ────────────────────────────────────────────── */
.node-badge {
  font-size: 10px;
  font-weight: 700;
  fill: white;
  text-anchor: middle;
  dominant-baseline: central;
  pointer-events: none;
}

/* ── Pulse Animation ──────────────────────────────────────────────────────── */
@keyframes node-pulse {
  0% { r: 0; opacity: 0.6; }
  100% { r: 30; opacity: 0; }
}

/* ── Edge Drawing Animation ───────────────────────────────────────────────── */
.edge-line {
  stroke: var(--edge-color);
  stroke-width: 1.5;
  fill: none;
}

/* ── Node Fade-in ─────────────────────────────────────────────────────────── */
.node-group {
  cursor: pointer;
  transition: opacity 0.3s;
}
.node-group.entering {
  animation: node-enter 0.4s ease-out;
}
@keyframes node-enter {
  0% { opacity: 0; transform: scale(0.5); }
  100% { opacity: 1; transform: scale(1); }
}

/* ── Hidden utility ───────────────────────────────────────────────────────── */
.hidden { display: none !important; }
```

- [ ] **Step 3: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/dashboard/client/index.html src/dashboard/client/styles.css
git commit -m "feat(dashboard): add HTML shell and dark theme CSS"
```

---

### Task 9: Client App (`app.js`) - WebSocket + State Management

**Files:**
- Create: `src/dashboard/client/app.js`

**Dependencies:** Task 8 (HTML structure), Task 1 (event types, used as reference)

This is the client orchestrator. It manages WebSocket connection, application state, and mode switching (scan vs explore).

- [ ] **Step 1: Write app.js**

```javascript
// src/dashboard/client/app.js

// ── Application State ────────────────────────────────────────────────────────

const state = {
  mode: "scan", // "scan" | "explore"
  nodes: [],    // { id, lane, type, data, findings: [], maxSeverity: null }
  edges: [],    // { source, target, type }
  findings: [], // all findings received
  stats: { routes: 0, endpoints: 0, findings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  selectedNodeId: null,
  activeSeverityFilter: "all",
  scanComplete: false,
};

// ── Lane Classification ──────────────────────────────────────────────────────

function classifyLane(eventType, data) {
  if (eventType === "recon:route") return "frontend";
  if (eventType === "recon:endpoint") return "api";
  if (eventType === "recon:datamodel") return "database";
  if (eventType === "recon:external") return "external";
  if (eventType === "recon:authflow") return "api";
  if (eventType === "recon:envvar") return "external";
  return "api";
}

function nodeId(eventType, data) {
  if (data.path) return data.path;
  if (data.name) return data.name;
  return `${eventType}-${Math.random().toString(36).slice(2, 8)}`;
}

// ── Severity Ranking ─────────────────────────────────────────────────────────

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function maxSeverity(a, b) {
  if (!a) return b;
  if (!b) return a;
  return (SEVERITY_RANK[a] ?? 0) >= (SEVERITY_RANK[b] ?? 0) ? a : b;
}

// ── Event Handlers ───────────────────────────────────────────────────────────

function handleScanStart(event) {
  updateStatusText("Scanning...");
  setStatusClass("scanning");
  addLogEntry("info", `Scan started: ${event.project}`);
}

function handleScanComplete(event) {
  state.scanComplete = true;
  state.mode = "explore";
  updateStatusText(`Complete (${event.summary.durationMs}ms)`);
  setStatusClass("complete");
  addLogEntry("info", `Scan complete: ${event.summary.findings.critical + event.summary.findings.high + event.summary.findings.medium + event.summary.findings.low} findings`);
  transitionToExploreMode();
}

function handleLayerStart(event) {
  addLogEntry("info", `Layer: ${event.layer} started`);
  updateLaneStatus(event.layer, "scanning", "scanning...");
}

function handleLayerComplete(event) {
  addLogEntry("info", `Layer: ${event.layer} complete (${event.durationMs}ms)`);
  // Lane status gets updated with counts after all events for that layer arrive
}

function handleReconEvent(event) {
  const lane = classifyLane(event.type, event.data);
  const id = nodeId(event.type, event.data);

  // Deduplicate by id
  if (state.nodes.find((n) => n.id === id)) return;

  const node = { id, lane, type: event.type, data: event.data, findings: [], maxSeverity: null };
  state.nodes.push(node);

  // Update stats
  if (event.type === "recon:route") state.stats.routes++;
  if (event.type === "recon:endpoint") state.stats.endpoints++;
  updateStatsPanel();

  // Add to graph
  if (typeof addNode === "function") addNode(node);

  addLogEntry("info", `${lane}: ${id}`);
}

function handleFinding(event) {
  const finding = event.data;
  state.findings.push(finding);

  // Update severity stats
  state.stats.findings++;
  state.stats[finding.severity] = (state.stats[finding.severity] || 0) + 1;
  updateStatsPanel();

  // Attach to matching node
  const matchNode = state.nodes.find((n) => n.data.file === finding.file);
  if (matchNode) {
    matchNode.findings.push(finding);
    matchNode.maxSeverity = maxSeverity(matchNode.maxSeverity, finding.severity);
    if (typeof updateNodeSeverity === "function") updateNodeSeverity(matchNode);
  }

  const severityLabel = finding.severity.toUpperCase();
  addLogEntry(finding.severity === "critical" || finding.severity === "high" ? "error" : "warn",
    `[${severityLabel}] ${finding.title}`);
}

function handleEdge(event) {
  state.edges.push(event.data);
  if (typeof addEdge === "function") addEdge(event.data);
}

function handleLog(event) {
  addLogEntry(event.level, event.message);
}

// ── WebSocket ────────────────────────────────────────────────────────────────

function connectWebSocket() {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${protocol}//${location.host}/ws`);

  ws.onopen = () => {
    updateStatusText("Connected, waiting for scan...");
  };

  ws.onmessage = (msg) => {
    const event = JSON.parse(msg.data);
    switch (event.type) {
      case "scan:start":      handleScanStart(event); break;
      case "scan:complete":   handleScanComplete(event); break;
      case "layer:start":     handleLayerStart(event); break;
      case "layer:complete":  handleLayerComplete(event); break;
      case "recon:route":
      case "recon:endpoint":
      case "recon:datamodel":
      case "recon:authflow":
      case "recon:envvar":
      case "recon:external":  handleReconEvent(event); break;
      case "finding":         handleFinding(event); break;
      case "edge":            handleEdge(event); break;
      case "log":             handleLog(event); break;
    }
  };

  ws.onclose = () => {
    if (!state.scanComplete) {
      updateStatusText("Disconnected");
      setStatusClass("");
    }
  };
}

// ── Mode Switching ───────────────────────────────────────────────────────────

function transitionToExploreMode() {
  document.getElementById("sidebar-scan").classList.add("hidden");
  document.getElementById("sidebar-explore").classList.remove("hidden");
  document.getElementById("severity-filters").classList.remove("hidden");

  // Update lane headers with final counts
  const laneCounts = {};
  const laneIssues = {};
  for (const node of state.nodes) {
    laneCounts[node.lane] = (laneCounts[node.lane] || 0) + 1;
    if (node.findings.length > 0) {
      laneIssues[node.lane] = (laneIssues[node.lane] || 0) + node.findings.length;
    }
  }
  for (const lane of ["frontend", "api", "database", "external"]) {
    const count = laneCounts[lane] || 0;
    const issues = laneIssues[lane] || 0;
    const statusText = issues > 0 ? `${count} (${issues} issues)` : `${count}`;
    const statusState = issues > 0 ? "issues" : "complete";
    updateLaneStatus(mapLayerToLane(lane), statusState, statusText);
  }
}

function mapLayerToLane(lane) {
  // Direct mapping - lanes and layer names may not 1:1
  // recon layer populates all lanes; rules/ai produce findings
  return lane;
}

// ── Severity Filtering ───────────────────────────────────────────────────────

document.querySelectorAll(".filter-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelector(".filter-btn.active")?.classList.remove("active");
    btn.classList.add("active");
    state.activeSeverityFilter = btn.dataset.severity;
    if (typeof applySeverityFilter === "function") applySeverityFilter(state.activeSeverityFilter);
  });
});

// ── Node Selection (called from graph.js) ────────────────────────────────────

function selectNode(nodeId) {
  state.selectedNodeId = nodeId;
  const node = state.nodes.find((n) => n.id === nodeId);
  if (node && typeof showNodeDetail === "function") {
    showNodeDetail(node);
  }
}

function deselectNode() {
  state.selectedNodeId = null;
  if (typeof clearNodeDetail === "function") {
    clearNodeDetail();
  }
}

// ── Boot ─────────────────────────────────────────────────────────────────────

connectWebSocket();
```

- [ ] **Step 2: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/dashboard/client/app.js
git commit -m "feat(dashboard): add client app with WebSocket state management"
```

---

### Task 10: D3 Graph Renderer (`graph.js`)

**Files:**
- Create: `src/dashboard/client/graph.js`

**Dependencies:** Task 8 (SVG container), Task 9 (state object, callbacks)

This is the largest client file. It manages the D3 force simulation with four constrained lanes.

- [ ] **Step 1: Write graph.js**

```javascript
// src/dashboard/client/graph.js

// ── D3 Setup ─────────────────────────────────────────────────────────────────

const svg = d3.select("#graph-svg");
const width = () => document.getElementById("graph-area").clientWidth;
const height = () => document.getElementById("graph-area").clientHeight;

// Lane x-band positions (4 equal columns)
const LANES = ["frontend", "api", "database", "external"];
const LANE_COLORS = {
  frontend: { fill: "#0f4c75", stroke: "#7bb3e0" },
  api:      { fill: "#0f4c75", stroke: "#7bb3e0" },
  database: { fill: "#14532d", stroke: "#4ade80" },
  external: { fill: "#4a1d96", stroke: "#a78bfa" },
};

function laneX(lane) {
  const i = LANES.indexOf(lane);
  const w = width();
  const laneWidth = w / LANES.length;
  return laneWidth * i + laneWidth / 2;
}

function laneBounds(lane) {
  const i = LANES.indexOf(lane);
  const w = width();
  const laneWidth = w / LANES.length;
  return { x0: laneWidth * i + 30, x1: laneWidth * (i + 1) - 30 };
}

// ── Draw Lane Backgrounds ────────────────────────────────────────────────────

const laneGroup = svg.append("g").attr("class", "lanes");

function drawLanes() {
  laneGroup.selectAll("rect").remove();
  const w = width();
  const h = height();
  const laneWidth = w / LANES.length;

  LANES.forEach((lane, i) => {
    laneGroup.append("rect")
      .attr("x", laneWidth * i)
      .attr("y", 0)
      .attr("width", laneWidth)
      .attr("height", h)
      .attr("fill", i % 2 === 0 ? "#0d2137" : "#0a1d30")
      .attr("stroke", "#1e3a5f")
      .attr("stroke-width", 0.5);
  });
}

drawLanes();

// ── Force Simulation ─────────────────────────────────────────────────────────

const simulation = d3.forceSimulation()
  .force("charge", d3.forceManyBody().strength(-80))
  .force("collide", d3.forceCollide().radius(35))
  .force("y", d3.forceY(height() / 2).strength(0.03))
  .on("tick", ticked);

simulation.stop(); // Start manually when nodes arrive

const edgeGroup = svg.append("g").attr("class", "edges");
const nodeGroup = svg.append("g").attr("class", "nodes");
const pulseGroup = svg.append("g").attr("class", "pulses");

let simNodes = [];
let simEdges = [];

// ── Node Rendering ───────────────────────────────────────────────────────────

const NODE_RADIUS = 20;
const RECT_W = 50;
const RECT_H = 28;

function nodeShape(lane) {
  // frontend = circle, api = rounded rect, database = pill, external = diamond
  return lane === "frontend" ? "circle" : lane === "database" ? "pill" : lane === "external" ? "diamond" : "rect";
}

function addNode(node) {
  const bounds = laneBounds(node.lane);
  node.x = bounds.x0 + Math.random() * (bounds.x1 - bounds.x0);
  node.y = 60 + Math.random() * (height() - 120);

  simNodes.push(node);
  simulation.nodes(simNodes);
  simulation.alpha(0.3).restart();

  renderNodes();
}

function renderNodes() {
  const groups = nodeGroup.selectAll(".node-group")
    .data(simNodes, (d) => d.id);

  const enter = groups.enter()
    .append("g")
    .attr("class", "node-group entering")
    .attr("transform", (d) => `translate(${d.x},${d.y})`)
    .on("click", (event, d) => {
      if (state.mode === "explore") {
        event.stopPropagation();
        selectNode(d.id);
        highlightSelected(d.id);
      }
    });

  // Draw shapes based on lane
  enter.each(function(d) {
    const g = d3.select(this);
    const colors = LANE_COLORS[d.lane];
    const shape = nodeShape(d.lane);

    if (shape === "circle") {
      g.append("circle")
        .attr("r", NODE_RADIUS)
        .attr("fill", colors.fill)
        .attr("stroke", colors.stroke)
        .attr("stroke-width", 1.5)
        .attr("class", "node-shape");
    } else if (shape === "rect") {
      g.append("rect")
        .attr("x", -RECT_W / 2).attr("y", -RECT_H / 2)
        .attr("width", RECT_W).attr("height", RECT_H)
        .attr("rx", 6)
        .attr("fill", colors.fill)
        .attr("stroke", colors.stroke)
        .attr("stroke-width", 1.5)
        .attr("class", "node-shape");
    } else if (shape === "pill") {
      g.append("rect")
        .attr("x", -RECT_W / 2).attr("y", -RECT_H / 2)
        .attr("width", RECT_W).attr("height", RECT_H)
        .attr("rx", RECT_H / 2)
        .attr("fill", colors.fill)
        .attr("stroke", colors.stroke)
        .attr("stroke-width", 1.5)
        .attr("class", "node-shape");
    } else if (shape === "diamond") {
      const s = NODE_RADIUS;
      g.append("polygon")
        .attr("points", `0,${-s} ${s},0 0,${s} ${-s},0`)
        .attr("fill", colors.fill)
        .attr("stroke", colors.stroke)
        .attr("stroke-width", 1.5)
        .attr("class", "node-shape");
    }

    // Label
    const label = d.id.length > 12 ? d.id.slice(-12) : d.id;
    g.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", shape === "circle" || shape === "diamond" ? NODE_RADIUS + 14 : RECT_H / 2 + 14)
      .attr("font-size", "10px")
      .attr("fill", "#94a3b8")
      .text(label);
  });

  // Remove animation class after it plays
  setTimeout(() => {
    enter.classed("entering", false);
  }, 400);
}

// ── Severity Update ──────────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  critical: { fill: "#991b1b", stroke: "#ef4444", glow: "rgba(239,68,68,0.4)" },
  high:     { fill: "#7c2d12", stroke: "#f97316", glow: "rgba(249,115,22,0.3)" },
  medium:   { fill: "#78350f", stroke: "#f59e0b", glow: "rgba(245,158,11,0.2)" },
};

function updateNodeSeverity(node) {
  const colors = SEVERITY_COLORS[node.maxSeverity];
  if (!colors) return;

  const g = nodeGroup.selectAll(".node-group")
    .filter((d) => d.id === node.id);

  // Update shape colors
  g.select(".node-shape")
    .transition().duration(400)
    .attr("fill", colors.fill)
    .attr("stroke", colors.stroke);

  // Add/update badge
  let badge = g.select(".badge-group");
  if (badge.empty()) {
    badge = g.append("g").attr("class", "badge-group");
    badge.append("circle")
      .attr("r", 8)
      .attr("cx", NODE_RADIUS - 2)
      .attr("cy", -NODE_RADIUS + 2);
    badge.append("text")
      .attr("class", "node-badge")
      .attr("x", NODE_RADIUS - 2)
      .attr("y", -NODE_RADIUS + 2);
  }
  badge.select("circle").attr("fill", colors.stroke);
  badge.select("text").text(node.findings.length);

  // Pulse animation
  const pulse = pulseGroup.append("circle")
    .attr("cx", node.x)
    .attr("cy", node.y)
    .attr("r", 0)
    .attr("fill", "none")
    .attr("stroke", colors.stroke)
    .attr("stroke-width", 2)
    .attr("opacity", 0.6);

  pulse.transition().duration(800)
    .attr("r", 40)
    .attr("opacity", 0)
    .remove();
}

// ── Edge Rendering ───────────────────────────────────────────────────────────

function addEdge(edgeData) {
  const source = simNodes.find((n) => n.id === edgeData.source);
  const target = simNodes.find((n) => n.id === edgeData.target);
  if (!source || !target) return;

  simEdges.push({ source, target, type: edgeData.type });
  renderEdges();
}

function renderEdges() {
  const lines = edgeGroup.selectAll(".edge-line")
    .data(simEdges, (d) => `${d.source.id}-${d.target.id}`);

  lines.enter()
    .append("path")
    .attr("class", "edge-line")
    .attr("d", (d) => {
      const mx = (d.source.x + d.target.x) / 2;
      const my = (d.source.y + d.target.y) / 2 - 20;
      return `M${d.source.x},${d.source.y} Q${mx},${my} ${d.target.x},${d.target.y}`;
    })
    .attr("stroke-dasharray", function() { return this.getTotalLength(); })
    .attr("stroke-dashoffset", function() { return this.getTotalLength(); })
    .transition().duration(600)
    .attr("stroke-dashoffset", 0);
}

// ── Selection Highlight ──────────────────────────────────────────────────────

function highlightSelected(nodeId) {
  nodeGroup.selectAll(".node-group").each(function(d) {
    const g = d3.select(this);
    if (d.id === nodeId) {
      g.select(".node-shape")
        .attr("stroke", "#fbbf24")
        .attr("stroke-width", 3)
        .attr("filter", "drop-shadow(0 0 6px rgba(251,191,36,0.4))");
    } else {
      const colors = SEVERITY_COLORS[d.maxSeverity] || LANE_COLORS[d.lane];
      g.select(".node-shape")
        .attr("stroke", colors.stroke)
        .attr("stroke-width", 1.5)
        .attr("filter", null);
    }
  });
}

// ── Severity Filter ──────────────────────────────────────────────────────────

function applySeverityFilter(level) {
  const rank = { all: -1, critical: 4, high: 3, medium: 2 };
  const minRank = rank[level] ?? -1;

  nodeGroup.selectAll(".node-group")
    .transition().duration(300)
    .style("opacity", (d) => {
      if (minRank <= 0) return 1;
      const nodeRank = SEVERITY_RANK[d.maxSeverity] ?? 0;
      return nodeRank >= minRank ? 1 : 0.15;
    });
}

// ── Tick (Force Simulation) ──────────────────────────────────────────────────

function ticked() {
  // Constrain nodes to their lane x-bounds
  for (const d of simNodes) {
    const bounds = laneBounds(d.lane);
    d.x = Math.max(bounds.x0, Math.min(bounds.x1, d.x));
    d.y = Math.max(50, Math.min(height() - 30, d.y));
  }

  nodeGroup.selectAll(".node-group")
    .attr("transform", (d) => `translate(${d.x},${d.y})`);

  edgeGroup.selectAll(".edge-line")
    .attr("d", (d) => {
      const mx = (d.source.x + d.target.x) / 2;
      const my = (d.source.y + d.target.y) / 2 - 20;
      return `M${d.source.x},${d.source.y} Q${mx},${my} ${d.target.x},${d.target.y}`;
    });
}

// ── Click on empty space to deselect ─────────────────────────────────────────

svg.on("click", () => {
  if (state.mode === "explore") {
    deselectNode();
    highlightSelected(null);
  }
});

// ── Resize Handling ──────────────────────────────────────────────────────────

window.addEventListener("resize", () => {
  drawLanes();
  simulation.force("y", d3.forceY(height() / 2).strength(0.03));
  simulation.alpha(0.3).restart();
});
```

- [ ] **Step 2: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/dashboard/client/graph.js
git commit -m "feat(dashboard): add D3 force graph with lanes, nodes, edges, animations"
```

---

### Task 11: Sidebar (`sidebar.js`)

**Files:**
- Create: `src/dashboard/client/sidebar.js`

**Dependencies:** Task 8 (HTML sidebar elements), Task 9 (state)

- [ ] **Step 1: Write sidebar.js**

```javascript
// src/dashboard/client/sidebar.js

// ── Status Helpers ───────────────────────────────────────────────────────────

function updateStatusText(text) {
  document.getElementById("scan-status-text").textContent = text;
}

function setStatusClass(cls) {
  const el = document.getElementById("scan-status");
  el.classList.remove("scanning", "complete");
  if (cls) el.classList.add(cls);
}

// ── Stats Panel ──────────────────────────────────────────────────────────────

function updateStatsPanel() {
  document.getElementById("stat-routes").textContent = state.stats.routes;
  document.getElementById("stat-endpoints").textContent = state.stats.endpoints;
  document.getElementById("stat-findings").textContent = state.stats.findings;
  document.getElementById("stat-critical").textContent = state.stats.critical;
  document.getElementById("stat-high").textContent = state.stats.high;
  document.getElementById("stat-medium").textContent = state.stats.medium;
  document.getElementById("stat-low").textContent = state.stats.low;
}

// ── Activity Log ─────────────────────────────────────────────────────────────

function addLogEntry(level, message) {
  const container = document.getElementById("log-entries");
  const entry = document.createElement("div");
  entry.className = `log-entry ${level}`;

  const time = new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  entry.innerHTML = `<span class="log-time">${time}</span>${escapeHtml(message)}`;

  container.appendChild(entry);
  container.scrollTop = container.scrollHeight;
}

// ── Lane Status ──────────────────────────────────────────────────────────────

function updateLaneStatus(layerOrLane, statusState, statusText) {
  // Map layer names to lane names
  const laneMap = { recon: null, rules: null, ai: null, frontend: "frontend", api: "api", database: "database", external: "external" };
  const lane = laneMap[layerOrLane] ?? layerOrLane;
  if (!lane) return; // recon/rules/ai don't map directly to a single lane

  const header = document.querySelector(`.lane-header[data-lane="${lane}"]`);
  if (!header) return;
  header.setAttribute("data-state", statusState);
  const statusEl = header.querySelector(".lane-status");
  if (statusEl) statusEl.textContent = statusText;
}

// ── Node Detail (Exploration Mode) ───────────────────────────────────────────

function showNodeDetail(node) {
  const titleEl = document.getElementById("node-detail-title");
  const bodyEl = document.getElementById("node-detail-body");
  const findingsEl = document.getElementById("node-findings-list");

  titleEl.textContent = node.id;

  // Build detail body
  let html = "";
  if (node.data.file) {
    html += `<div class="detail-field"><div class="detail-label">File</div><div class="detail-value">${escapeHtml(node.data.file)}</div></div>`;
  }
  if (node.data.method) {
    html += `<div class="detail-field"><div class="detail-label">Method</div><div class="detail-value">${escapeHtml(node.data.method)}</div></div>`;
  }

  // Tags
  const tags = [];
  if (node.data.hasAuthCheck !== undefined) {
    tags.push(node.data.hasAuthCheck
      ? '<span class="detail-tag auth">auth</span>'
      : '<span class="detail-tag no-auth">no auth</span>');
  }
  if (node.data.hasValidation) {
    tags.push('<span class="detail-tag validated">validated</span>');
  }
  if (tags.length > 0) {
    html += `<div class="detail-field"><div class="detail-label">Tags</div><div>${tags.join("")}</div></div>`;
  }

  bodyEl.innerHTML = html || '<p class="muted">No additional details.</p>';

  // Build findings list
  if (node.findings.length === 0) {
    findingsEl.innerHTML = '<p class="muted">No findings for this node.</p>';
  } else {
    findingsEl.innerHTML = node.findings.map((f) => `
      <div class="finding-card ${f.severity}">
        <div class="finding-title">${escapeHtml(f.title)}</div>
        <div class="finding-location">${escapeHtml(f.file)}${f.line ? `:${f.line}` : ""}</div>
        ${f.remediation ? `<div class="finding-remediation">${escapeHtml(f.remediation)}</div>` : ""}
      </div>
    `).join("");
  }
}

function clearNodeDetail() {
  document.getElementById("node-detail-title").textContent = "Select a node";
  document.getElementById("node-detail-body").innerHTML = '<p class="muted">Click a node in the graph to see details.</p>';
  document.getElementById("node-findings-list").innerHTML = "";
}

// ── Utility ──────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add src/dashboard/client/sidebar.js
git commit -m "feat(dashboard): add sidebar with stats, log, and node detail panels"
```

---

### Task 12: Integration Test

**Files:**
- Create: `tests/dashboard/integration.test.ts`

**Dependencies:** All previous tasks

This test runs a real scan with the emitter and verifies events flow correctly through the system.

- [ ] **Step 1: Write the integration test**

```typescript
// tests/dashboard/integration.test.ts
import { describe, it, expect, afterEach } from "vitest";
import { ScanEventEmitter } from "../../src/dashboard/events.js";
import { startDashboard, type DashboardHandle } from "../../src/dashboard/server.js";
import type { ScanEvent } from "../../src/dashboard/events.js";
import WebSocket from "ws";

describe("Dashboard integration", () => {
  let handle: DashboardHandle | null = null;

  afterEach(async () => {
    if (handle) {
      await handle.close();
      handle = null;
    }
  });

  it("streams a full scan lifecycle to WebSocket client", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });

    const ws = new WebSocket(`ws://localhost:${handle.port}/ws`);
    const received: ScanEvent[] = [];

    await new Promise<void>((resolve) => ws.on("open", resolve));
    ws.on("message", (data) => received.push(JSON.parse(data.toString())));

    // Simulate a scan lifecycle
    emitter.emitEvent({ type: "scan:start", project: "/tmp/test-project", timestamp: Date.now() });
    emitter.emitEvent({ type: "layer:start", layer: "recon", timestamp: Date.now() });
    emitter.emitEvent({
      type: "recon:route",
      data: { path: "/", method: "GET", file: "src/app/page.tsx", isApi: false, hasAuthCheck: false },
    });
    emitter.emitEvent({
      type: "recon:endpoint",
      data: { path: "/api/users", method: "GET", file: "src/app/api/users/route.ts", hasValidation: true, hasAuthCheck: true, usesServiceRole: false },
    });
    emitter.emitEvent({ type: "layer:complete", layer: "recon", durationMs: 500, timestamp: Date.now() });
    emitter.emitEvent({ type: "layer:start", layer: "rules", timestamp: Date.now() });
    emitter.emitEvent({
      type: "finding",
      data: {
        id: "SEC-001",
        severity: "high",
        title: "Missing rate limiting",
        file: "src/app/api/users/route.ts",
        line: 15,
        domain: "api-security",
        layer: "rules",
        remediation: "Add rate limiting middleware",
      },
    });
    emitter.emitEvent({ type: "layer:complete", layer: "rules", durationMs: 200, timestamp: Date.now() });
    emitter.emitEvent({
      type: "scan:complete",
      summary: {
        routes: 1,
        endpoints: 1,
        dataModels: 0,
        externalServices: 0,
        findings: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        durationMs: 700,
      },
      timestamp: Date.now(),
    });

    // Allow delivery
    await new Promise((r) => setTimeout(r, 100));

    ws.close();

    // Verify the event sequence
    expect(received.length).toBeGreaterThanOrEqual(8);
    expect(received[0].type).toBe("scan:start");
    expect(received[1].type).toBe("layer:start");

    const routes = received.filter((e) => e.type === "recon:route");
    expect(routes).toHaveLength(1);

    const endpoints = received.filter((e) => e.type === "recon:endpoint");
    expect(endpoints).toHaveLength(1);

    const findings = received.filter((e) => e.type === "finding");
    expect(findings).toHaveLength(1);
    if (findings[0].type === "finding") {
      expect(findings[0].data.severity).toBe("high");
    }

    const complete = received.find((e) => e.type === "scan:complete");
    expect(complete).toBeDefined();
    if (complete?.type === "scan:complete") {
      expect(complete.summary.routes).toBe(1);
    }
  });

  it("serves the dashboard client at /", async () => {
    const emitter = new ScanEventEmitter();
    handle = await startDashboard(emitter, { port: 0, openBrowser: false });

    const res = await fetch(`http://localhost:${handle.port}/`);
    const html = await res.text();
    expect(html).toContain("Sentinel Dashboard");
    expect(html).toContain("graph-svg");
    expect(html).toContain("d3.v7.min.js");
  });
});
```

- [ ] **Step 2: Run all tests**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx vitest run`
Expected: All tests pass

- [ ] **Step 3: Run typecheck and lint**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsc --noEmit && npx eslint src tests --ext .ts`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
cd /Users/tywells/Downloads/projects/security-agent-dev
git add tests/dashboard/integration.test.ts
git commit -m "test(dashboard): add integration test for full scan lifecycle"
```

---

### Task 13: Manual Smoke Test

**Files:** None (verification only)

**Dependencies:** All previous tasks

- [ ] **Step 1: Build the project**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npm run build`
Expected: PASS

- [ ] **Step 2: Run Sentinel with `--dashboard` against a real project**

Run: `cd /Users/tywells/Downloads/projects/security-agent-dev && npx tsx src/cli.ts scan /Users/tywells/Downloads/projects/wise-time --dashboard --port 4400`

Expected:
- Browser opens to `http://localhost:4400`
- Dashboard shows "Scanning..." with amber dot
- Nodes appear in lanes as recon discovers routes/endpoints
- Findings appear with colored badges and pulse animations
- After scan completes, status changes to green "Complete"
- Clicking a node shows detail in sidebar
- Severity filters dim non-matching nodes
- Ctrl+C exits cleanly

- [ ] **Step 3: Take screenshots for coaching demo prep**

Save screenshots of:
1. Mid-scan (nodes animating in)
2. Post-scan (full graph with findings)
3. Node selected (sidebar detail view)

---

## Spec Coverage Verification

| Spec Section | Task(s) |
|---|---|
| `--dashboard` flag activation | Task 7 (CLI), Task 3 (scan.ts wiring) |
| ScanEventEmitter + typed events | Task 1 |
| Layer instrumentation (recon) | Task 4 |
| Layer instrumentation (rules) | Task 5 |
| Layer instrumentation (AI) | Task 6 |
| Express+WebSocket server | Task 2 |
| D3 hybrid lane graph | Task 10 |
| Node shapes per lane | Task 10 |
| Severity colors + badges + pulse | Task 10 |
| Edge rendering | Task 10 |
| Scan mode (stats + log) | Task 9, Task 11 |
| Exploration mode (node detail + findings) | Task 9, Task 11 |
| Lane header status | Task 11 |
| Severity filtering | Task 9, Task 10 |
| Dark theme | Task 8 |
| CLI `--port` option | Task 7 |
| Keep process alive after scan | Task 3 |
| No changes to existing output modes | Tasks 3-6 (optional emitter, no behavior change without it) |
