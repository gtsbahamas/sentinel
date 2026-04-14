// src/dashboard/client/app.js

// ── Application State ────────────────────────────────────────────────────────

const state = {
  mode: "scan", // "scan" | "explore"
  nodes: [],    // { id, lane, type, data, findings: [], findingGroups: [], maxSeverity: null }
  edges: [],    // { source, target, type }
  findings: [], // all raw findings received
  stats: { routes: 0, endpoints: 0, findings: 0, classes: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
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
// SEVERITY_RANK is defined in graph.js (loaded first)

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
}

function handleReconEvent(event) {
  const lane = classifyLane(event.type, event.data);
  const id = nodeId(event.type, event.data);

  // Deduplicate by id
  if (state.nodes.find((n) => n.id === id)) return;

  const node = { id, lane, type: event.type, data: event.data, findings: [], findingGroups: [], maxSeverity: null };
  state.nodes.push(node);

  // Update stats
  if (event.type === "recon:route") state.stats.routes++;
  if (event.type === "recon:endpoint") state.stats.endpoints++;
  updateStatsPanel();

  // Add to graph
  if (typeof addNode === "function") addNode(node);

  addLogEntry("info", `${lane}: ${id}`);
}

// Group a finding into a node's findingGroups array. Returns true if this created a new group.
function addToFindingGroup(node, finding) {
  const existing = node.findingGroups.find((g) => g.title === finding.title);
  if (existing) {
    existing.instances.push({ file: finding.file, line: finding.line, id: finding.id });
    existing.severity = maxSeverity(existing.severity, finding.severity);
    return false;
  }
  node.findingGroups.push({
    title: finding.title,
    severity: finding.severity,
    domain: finding.domain,
    impact: finding.impact,
    remediation: finding.remediation,
    instances: [{ file: finding.file, line: finding.line, id: finding.id }],
  });
  return true;
}

function handleFinding(event) {
  const finding = event.data;
  state.findings.push(finding);

  // Update raw instance stats
  state.stats.findings++;
  state.stats[finding.severity] = (state.stats[finding.severity] || 0) + 1;

  // Attach to matching node, grouped by title
  const matchNode = state.nodes.find((n) => n.data.file === finding.file);
  if (matchNode) {
    matchNode.findings.push(finding);
    const isNewClass = addToFindingGroup(matchNode, finding);
    matchNode.maxSeverity = maxSeverity(matchNode.maxSeverity, finding.severity);
    // Badge shows distinct vulnerability classes, not raw count
    if (typeof updateNodeSeverity === "function") updateNodeSeverity(matchNode);
  }

  // Track distinct classes globally
  const isNewGlobal = !state.findings.slice(0, -1).some((f) => f.title === finding.title);
  if (isNewGlobal) state.stats.classes++;

  updateStatsPanel();

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

  // Update lane headers with final counts (distinct vulnerability classes, not raw instances)
  const laneCounts = {};
  const laneClasses = {};
  for (const node of state.nodes) {
    laneCounts[node.lane] = (laneCounts[node.lane] || 0) + 1;
    if (node.findingGroups.length > 0) {
      laneClasses[node.lane] = (laneClasses[node.lane] || 0) + node.findingGroups.length;
    }
  }
  for (const lane of ["frontend", "api", "database", "external"]) {
    const count = laneCounts[lane] || 0;
    const classes = laneClasses[lane] || 0;
    const statusText = classes > 0 ? `${count} (${classes} issues)` : `${count}`;
    const statusState = classes > 0 ? "issues" : "complete";
    updateLaneStatus(lane, statusState, statusText);
  }
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
