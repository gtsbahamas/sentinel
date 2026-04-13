# Sentinel Dashboard: D3.js Attack Surface Visualizer

## Purpose

Add a real-time browser-based dashboard to Sentinel that visualizes the attack surface as the scan runs. During the scan, nodes and findings animate onto a force-directed graph. After the scan completes, the dashboard transitions to an interactive exploration mode where users can click nodes, filter by severity, and drill into finding details.

Primary use case: live coaching demos for the Early AI-dopters security coaching sessions (starting April 29, 2026). Secondary use case: general-purpose scan visualization for any Sentinel user.

## Activation

```bash
sentinel scan ./my-project --dashboard
```

The `--dashboard` flag:
1. Starts a local Express server on port 4400
2. Opens the browser automatically to `http://localhost:4400`
3. Runs the scan normally, but emits typed events through an EventEmitter
4. The WebSocket server forwards events to the browser
5. After scan completes, the dashboard stays open for exploration

Without `--dashboard`, Sentinel behaves exactly as it does today. No changes to existing output modes (terminal, JSON, HTML).

## Architecture

```
sentinel scan . --dashboard
    │
    ├── ScanEventEmitter (new)
    │     Wraps existing scan orchestration
    │     Emits typed events as each discovery/finding occurs
    │
    ├── DashboardServer (new)
    │     Express: serves static D3 client from src/dashboard/client/
    │     WebSocket: forwards ScanEventEmitter events to browser
    │     Binds to localhost:4400 (configurable via --port)
    │
    └── D3 Client (new)
          Static HTML + JS bundle
          Subscribes to WebSocket
          Renders hybrid lane graph with D3.js force simulation
          Right sidebar with stats + activity log (scan mode)
          Right sidebar with node detail + findings (exploration mode)
```

### New Dependencies

- `express` - HTTP server for static files
- `ws` - WebSocket server
- `d3` - Visualization library (client-side, loaded via CDN or bundled)
- `open` - Opens browser automatically (already a common Node utility)

### File Structure

```
src/
├── dashboard/
│   ├── server.ts          # Express + WebSocket server
│   ├── events.ts          # ScanEventEmitter class + typed event definitions
│   └── client/
│       ├── index.html      # Dashboard shell
│       ├── app.js          # Main client entry, WebSocket subscription
│       ├── graph.js        # D3 force graph: lanes, nodes, edges, animations
│       ├── sidebar.js      # Stats panel, activity log, node detail panel
│       └── styles.css      # Dashboard styles (dark theme)
```

## Event System

### ScanEventEmitter

A new class that wraps the existing scan orchestration. Each layer's existing functions are instrumented to emit events as they discover components or produce findings. The scan orchestrator (`src/commands/scan.ts`) passes the emitter to each layer.

```typescript
// src/dashboard/events.ts

import { EventEmitter } from 'node:events';

type ScanEvent =
  | { type: 'scan:start'; project: string; timestamp: number }
  | { type: 'scan:complete'; summary: ScanSummary; timestamp: number }
  | { type: 'layer:start'; layer: LayerName; timestamp: number }
  | { type: 'layer:complete'; layer: LayerName; durationMs: number; timestamp: number }
  | { type: 'recon:route'; data: RouteData }
  | { type: 'recon:endpoint'; data: EndpointData }
  | { type: 'recon:datamodel'; data: DataModelData }
  | { type: 'recon:authflow'; data: AuthFlowData }
  | { type: 'recon:envvar'; data: EnvVarData }
  | { type: 'recon:external'; data: ExternalServiceData }
  | { type: 'finding'; data: Finding }
  | { type: 'edge'; data: EdgeData }
  | { type: 'log'; message: string; level: 'info' | 'warn' | 'error' };

type LayerName = 'recon' | 'rules' | 'probe' | 'ai';

interface ScanSummary {
  routes: number;
  endpoints: number;
  dataModels: number;
  externalServices: number;
  findings: { critical: number; high: number; medium: number; low: number; info: number };
  durationMs: number;
}

interface RouteData {
  path: string;
  method: string;
  file: string;
  isApi: boolean;
  hasAuthCheck: boolean;
}

interface EndpointData {
  path: string;
  method: string;
  file: string;
  hasValidation: boolean;
  hasAuthCheck: boolean;
  usesServiceRole: boolean;
}

interface DataModelData {
  name: string;
  file: string;
  hasRLS: boolean;
  policies: string[];
}

interface AuthFlowData {
  type: string;
  file: string;
  provider?: string;
}

interface EnvVarData {
  name: string;
  clientExposed: boolean;
  referencedIn: string[];
}

interface ExternalServiceData {
  name: string;
  type: 'api' | 'storage' | 'webhook' | 'automation';
  file: string;
}

interface EdgeData {
  source: string;  // node identifier (path or name)
  target: string;
  type: 'calls' | 'queries' | 'uses' | 'exposes';
}

class ScanEventEmitter extends EventEmitter {
  emit(event: 'scan-event', data: ScanEvent): boolean;
}
```

### Instrumentation Points

Each existing layer function gets an optional `emitter` parameter. When present, it emits events. When absent (no `--dashboard`), behavior is unchanged.

**Recon layer** (`src/layers/recon/`):
- `route-discovery.ts`: After discovering each route, emit `recon:route`
- `endpoint-discovery.ts`: After discovering each endpoint, emit `recon:endpoint`. Infer and emit `edge` events based on which routes map to which endpoints.
- `data-model-discovery.ts` (or equivalent): Emit `recon:datamodel`. Infer edges from endpoint → table relationships.
- `auth-discovery.ts`: Emit `recon:authflow`
- `env-discovery.ts`: Emit `recon:envvar`
- External services: Emit `recon:external`

**Rules layer** (`src/layers/rules/`):
- After each rule produces a finding, emit `finding`

**Probe layer** (`src/layers/probe/`):
- After each probe finding, emit `finding`

**AI layer** (`src/layers/ai/`):
- After each AI finding, emit `finding`

**Scan orchestrator** (`src/commands/scan.ts`):
- Before each layer: emit `layer:start`
- After each layer: emit `layer:complete`
- At start: emit `scan:start`
- At end: emit `scan:complete`

## Dashboard Server

```typescript
// src/dashboard/server.ts

import express from 'express';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import open from 'open';
import path from 'path';
import { ScanEventEmitter } from './events.js';

interface DashboardOptions {
  port?: number;       // default: 4400
  openBrowser?: boolean; // default: true
}

function startDashboard(emitter: ScanEventEmitter, options?: DashboardOptions): Promise<void> {
  const port = options?.port ?? 4400;
  const app = express();
  const server = createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });

  // Serve static client files
  app.use(express.static(path.join(__dirname, 'client')));

  // Forward scan events to all connected WebSocket clients
  emitter.on('scan-event', (event) => {
    const payload = JSON.stringify(event);
    wss.clients.forEach(client => {
      if (client.readyState === 1) client.send(payload);
    });
  });

  return new Promise((resolve) => {
    server.listen(port, () => {
      if (options?.openBrowser !== false) {
        open(`http://localhost:${port}`);
      }
      resolve();
    });
  });
}
```

## D3 Client

### Layout: Hybrid Lanes + Force

The graph area occupies ~70% width. Four vertical lanes: Frontend, API, Database, External.

Each lane:
- Has a header showing layer name and scan status
- Contains a D3 force simulation constrained to the lane's x-bounds
- Nodes use force to position organically within their lane
- Nodes cannot leave their lane (x-axis constrained), but float freely on y-axis

### Node Shapes

| Layer | Shape | Base Color | Border |
|-------|-------|-----------|--------|
| Frontend (routes) | Circle | `#0f4c75` | `#7bb3e0` |
| API (endpoints) | Rounded rect | `#0f4c75` | `#7bb3e0` |
| Database (tables) | Pill/capsule | `#14532d` | `#4ade80` |
| External (services) | Diamond | `#4a1d96` | `#a78bfa` |

### Severity Colors

When findings attach to a node, the node's fill and border change to reflect the highest severity:

| Severity | Fill | Border | Glow |
|----------|------|--------|------|
| Critical | `#991b1b` | `#ef4444` | `rgba(239,68,68,0.4)` |
| High | `#7c2d12` | `#f97316` | `rgba(249,115,22,0.3)` |
| Medium | `#78350f` | `#f59e0b` | `rgba(245,158,11,0.2)` |
| Low / Info | No change | No change | None |

### Finding-to-Node Mapping

When a `finding` event arrives, the client matches it to an existing node using the finding's `evidence[0].file` path. If the file matches a node's `file` property, the finding attaches to that node. If no match (e.g., a project-wide finding), the finding appears in the sidebar stats but does not attach to any specific node.

### Finding Badge

A small circular badge in the top-right corner of the node showing the finding count. Background matches the highest severity color. White text.

### Pulse Animation

When a new finding attaches to a node:
1. Badge count increments
2. Node border color transitions to severity color
3. Node emits a radial pulse animation (expanding ring that fades) lasting ~800ms
4. If severity increased, fill color transitions over ~400ms

### Edges

SVG lines connecting nodes across lanes. Drawn with a slight curve (quadratic bezier). Color: `#2d5a8e` at 50% opacity. Animate in with a "drawing" effect (stroke-dasharray transition).

### Scan Mode vs Exploration Mode

**Scan Mode** (while scan is running):
- Top bar shows "Scanning..." with pulsing amber indicator
- Lane headers show scan status: "scanning..." / "4 routes ✓" / "pending"
- Pending lanes are dimmed (opacity 0.5)
- Sidebar shows: stats panel (top) + activity log (bottom)
- Activity log auto-scrolls as new events arrive
- Nodes appear with a fade-in + scale animation
- No click interaction on nodes

**Exploration Mode** (after `scan:complete`):
- Top bar shows "Scan Complete" with green indicator
- Severity filter buttons appear in the top bar
- All lanes at full opacity
- Clicking a node selects it (gold highlight border `#fbbf24`, glow)
- Sidebar transitions to: selected node detail (top) + findings list (bottom)
- Node detail shows: path, file, method, tags (auth status, validation status)
- Findings list shows all findings for the selected node with severity badge, description, file:line, and remediation
- Clicking empty space deselects, sidebar reverts to summary stats
- Severity filters dim/hide nodes below the selected threshold

### Lane Header Status

Each lane header reflects its scan state:

| State | Display |
|-------|---------|
| Pending | `FRONTEND ○ pending` (dimmed) |
| Scanning | `API ● scanning...` (amber, lane border amber) |
| Complete (clean) | `DATABASE ✓ 4 tables` (green) |
| Complete (issues) | `API ✓ 5 (3 issues)` (red/amber based on max severity) |

## CLI Integration

### Flag Addition

Add `--dashboard` flag to the `scan` command in `src/cli.ts`:

```typescript
.option('--dashboard', 'Open real-time attack surface visualization in browser')
.option('--port <number>', 'Dashboard server port (default: 4400)', parseInt)
```

### Scan Command Modification

In `src/commands/scan.ts`, when `--dashboard` is passed:

1. Create `ScanEventEmitter` instance
2. Start dashboard server (awaits port binding)
3. Pass emitter to each layer function
4. Run scan as normal (layers emit events as they execute)
5. After scan completes, emit `scan:complete`
6. Keep process alive (server stays running until user hits Ctrl+C)
7. Terminal output still works normally alongside the dashboard

## Dark Theme

Background: `#0a1628` (deep navy)
Panels: `#0d1f33` (slightly lighter navy)
Lane backgrounds: `#0d2137`
Borders: `#1e3a5f`
Text primary: `#e2e8f0`
Text secondary: `#94a3b8`
Text muted: `#64748b`

## Scope Boundaries

### In Scope
- `--dashboard` flag on `sentinel scan`
- WebSocket event streaming from scan to browser
- D3.js hybrid lane visualization with force simulation
- Real-time node/edge/finding animation during scan
- Interactive exploration mode after scan
- Severity filtering
- Node click → detail panel
- Activity log during scan
- Summary stats

### Out of Scope
- Saving/exporting the dashboard state
- Multi-scan comparison
- Historical scan tracking
- Remote/shared dashboard (localhost only)
- Custom theme configuration
- Embedding the dashboard in other applications
- Modifying existing output formats (terminal, JSON, HTML remain unchanged)

## Testing

- Unit tests for `ScanEventEmitter` (event emission, type safety)
- Unit tests for edge inference logic
- Integration test: run scan with `--dashboard`, verify WebSocket receives expected events
- Manual verification: visual inspection of D3 rendering across different project sizes
- Test with 3 existing projects of varying complexity to validate layout behavior

## Performance Considerations

- D3 force simulation should handle up to ~200 nodes smoothly
- WebSocket messages are small JSON objects (~200 bytes each)
- No polling; purely event-driven
- Client does not re-render the entire graph on each event; D3's enter/update/exit pattern handles incremental updates
