// src/dashboard/client/app.js
// WebSocket connection, state management, event routing, mode switching.
// Loaded after graph.js and sidebar.js.

// ---- Application State ----
var state = {
  mode: 'scan',          // 'scan' | 'explore'
  nodes: [],             // { id, lane, label, type, data, findings[], findingGroups[], maxSeverity }
  edges: [],             // { source, target, type }
  findings: [],          // all raw findings
  selectedNodeId: null,
  activeFilters: new Set(['critical', 'high', 'medium', 'low']),
  scanComplete: false,
  projectName: '',
};

// ---- Lane Classification ----
function classifyLane(eventType, data) {
  if (eventType === 'recon:route' && !data.isApi) return 'frontend';
  if (eventType === 'recon:route' && data.isApi) return 'api';
  if (eventType === 'recon:endpoint') return 'api';
  if (eventType === 'recon:datamodel') return 'database';
  if (eventType === 'recon:external') return 'external';
  if (eventType === 'recon:authflow') return 'api';
  if (eventType === 'recon:envvar') return 'external';
  return 'api';
}

function deriveNodeId(eventType, data) {
  if (data.path) return data.path;
  if (data.name) return data.name;
  return eventType + '-' + Math.random().toString(36).slice(2, 8);
}

function deriveLabel(eventType, data) {
  if (data.path) {
    // Shorten path for display
    var parts = data.path.split('/').filter(Boolean);
    return parts.length > 0 ? parts[parts.length - 1] : data.path;
  }
  if (data.name) return data.name;
  return eventType.replace('recon:', '');
}

// ---- Severity helpers ----
// SEVERITY_RANK is defined in graph.js

function maxSeverity(a, b) {
  if (!a) return b;
  if (!b) return a;
  return (SEVERITY_RANK[a] || 0) >= (SEVERITY_RANK[b] || 0) ? a : b;
}

// ---- Finding grouping ----
function addToFindingGroup(node, finding) {
  var existing = node.findingGroups.find(function(g) { return g.title === finding.title; });
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

// ---- Event Handlers ----

function handleScanStart(event) {
  state.projectName = event.project || '';
  updateScanStatus('Scanning ' + state.projectName + '...');
  setScanDotClass('scanning');
  addScanLogEntry('info', 'Scan started: ' + state.projectName);
}

function handleScanComplete(event) {
  state.scanComplete = true;
  state.mode = 'explore';

  var durationSec = ((event.summary && event.summary.durationMs) || 0) / 1000;
  updateScanStatus('Scan complete - ' + state.projectName + ' (' + durationSec.toFixed(1) + 's)');
  setScanDotClass('complete');

  addScanLogEntry('info', 'Scan complete');
  transitionToExploreMode();
}

function handleLayerStart(event) {
  addScanLogEntry('info', 'Layer: ' + event.layer + ' started');
}

function handleLayerComplete(event) {
  addScanLogEntry('info', 'Layer: ' + event.layer + ' complete (' + event.durationMs + 'ms)');
}

function handleReconEvent(event) {
  var lane = classifyLane(event.type, event.data);
  var id = deriveNodeId(event.type, event.data);

  // Deduplicate by id
  if (state.nodes.find(function(n) { return n.id === id; })) return;

  var label = deriveLabel(event.type, event.data);
  var node = {
    id: id,
    lane: lane,
    label: label,
    type: event.type,
    data: event.data,
    findings: [],
    findingGroups: [],
    maxSeverity: null,
  };
  state.nodes.push(node);

  // Add to graph incrementally
  if (typeof addNode === 'function') addNode(node);

  addScanLogEntry('info', lane + ': ' + id);
}

function handleFinding(event) {
  var finding = event.data;
  state.findings.push(finding);

  // Attach to matching node by file
  var matchNode = state.nodes.find(function(n) { return n.data && n.data.file === finding.file; });
  if (matchNode) {
    matchNode.findings.push(finding);
    addToFindingGroup(matchNode, finding);
    matchNode.maxSeverity = maxSeverity(matchNode.maxSeverity, finding.severity);
    if (typeof updateNodeSeverity === 'function') updateNodeSeverity(matchNode);
  }

  var severityLabel = finding.severity.toUpperCase();
  var logLevel = (finding.severity === 'critical' || finding.severity === 'high') ? 'error' : 'warn';
  addScanLogEntry(logLevel, '[' + severityLabel + '] ' + finding.title);
}

function handleEdge(event) {
  state.edges.push(event.data);
  if (typeof addEdge === 'function') addEdge(event.data);
}

function handleLog(event) {
  addScanLogEntry(event.level, event.message);
}

// ---- WebSocket Connection ----

function connectWebSocket() {
  var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  var ws = new WebSocket(protocol + '//' + location.host + '/ws');

  ws.onopen = function() {
    updateScanStatus('Connected, waiting for scan...');
  };

  ws.onmessage = function(msg) {
    var event = JSON.parse(msg.data);
    switch (event.type) {
      case 'scan:start':      handleScanStart(event); break;
      case 'scan:complete':   handleScanComplete(event); break;
      case 'layer:start':     handleLayerStart(event); break;
      case 'layer:complete':  handleLayerComplete(event); break;
      case 'recon:route':
      case 'recon:endpoint':
      case 'recon:datamodel':
      case 'recon:authflow':
      case 'recon:envvar':
      case 'recon:external':  handleReconEvent(event); break;
      case 'finding':         handleFinding(event); break;
      case 'edge':            handleEdge(event); break;
      case 'log':             handleLog(event); break;
    }
  };

  ws.onclose = function() {
    if (!state.scanComplete) {
      updateScanStatus('Disconnected');
      setScanDotClass('');
    }
  };
}

// ---- Mode Switching ----

function transitionToExploreMode() {
  // Show severity filters
  var filters = document.getElementById('severityFilters');
  if (filters) filters.style.display = 'flex';

  // Show rescan button
  var rescan = document.getElementById('rescanBtn');
  if (rescan) rescan.style.display = 'flex';

  // Update detail panel title and render summary
  document.getElementById('detailTitle').textContent = 'Scan Summary';
  renderSummary();
}

// ---- Node Selection (from graph clicks) ----

function onNodeClick(node) {
  if (state.mode !== 'explore') return;

  // Toggle selection if clicking the same node
  if (state.selectedNodeId === node.id) {
    clearSelection();
    return;
  }

  state.selectedNodeId = node.id;

  // Update graph to show selection
  if (typeof redrawAllLanes === 'function') redrawAllLanes();

  // Update detail panel
  var label = node.label || node.id;
  document.getElementById('detailTitle').textContent = label;
  document.getElementById('backBtnWrapper').style.display = 'flex';
  document.getElementById('detailSubtitle').textContent = '';

  renderNodeDetail(node);
}

function clearSelection() {
  state.selectedNodeId = null;

  if (typeof redrawAllLanes === 'function') redrawAllLanes();

  document.getElementById('detailTitle').textContent = 'Scan Summary';
  document.getElementById('backBtnWrapper').style.display = 'none';
  document.getElementById('detailSubtitle').textContent = '';

  renderSummary();
}

// ---- Severity Filtering ----

document.querySelectorAll('.filter-btn').forEach(function(btn) {
  btn.addEventListener('click', function() {
    var severity = btn.dataset.severity;
    if (!severity) return;

    if (state.activeFilters.has(severity)) {
      if (state.activeFilters.size === 1) return; // keep at least one
      state.activeFilters.delete(severity);
      btn.className = 'filter-btn inactive';
    } else {
      state.activeFilters.add(severity);
      btn.className = 'filter-btn active-' + severity;
    }

    if (typeof applySeverityFilter === 'function') applySeverityFilter();
  });
});

// ---- Back button ----
var backBtn = document.getElementById('backBtn');
if (backBtn) {
  backBtn.addEventListener('click', function() {
    clearSelection();
  });
}

// ---- Boot ----

buildLanes();
connectWebSocket();
