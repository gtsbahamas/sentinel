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

// Classify a finding into a lane based on its file path and domain
function classifyFindingLane(finding) {
  var f = (finding.file || '').toLowerCase();
  // Database signals
  if (f.match(/\/(migration|schema|seed|drizzle|prisma|supabase\/)/)) return 'database';
  if (finding.domain === 'database' || finding.domain === 'data-exposure') return 'database';
  // Frontend signals
  if (f.match(/\/(components?|pages?|app\/(?!api).*page\.|views?|hooks?|client)\//)) return 'frontend';
  if (f.match(/\.(css|scss|html)$/)) return 'frontend';
  // External signals
  if (f.match(/\/(providers?|integrations?|external|webhooks?|oauth)\//)) return 'external';
  if (finding.domain === 'supply-chain') return 'external';
  // API signals
  if (f.match(/\/(api|routes?|server|middleware|edge-functions?|functions?)\//)) return 'api';
  if (f.match(/route\.(ts|js)$/)) return 'api';
  // Domain-based fallbacks
  if (finding.domain === 'auth-access-control') return 'api';
  if (finding.domain === 'api-security') return 'api';
  if (finding.domain === 'input-injection') return 'api';
  if (finding.domain === 'infrastructure') return 'external';
  // Default
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
  // Skip env vars — they're metadata, not attack surface components
  if (event.type === 'recon:envvar') return;

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

  // Try to attach to a matching node:
  // 1. Exact file match
  // 2. Finding file is inside node's directory (path containment)
  var matchNode = null;
  var findingFile = finding.file || '';
  for (var i = 0; i < state.nodes.length; i++) {
    var n = state.nodes[i];
    if (!n.data) continue;
    var nodeFile = n.data.file || '';
    // Exact match
    if (nodeFile && nodeFile === findingFile) { matchNode = n; break; }
    // Path containment: if node file is in same directory tree as finding
    if (nodeFile) {
      var nodeDir = nodeFile.substring(0, nodeFile.lastIndexOf('/'));
      if (nodeDir && findingFile.indexOf(nodeDir) === 0) {
        matchNode = n;
        // Don't break — a more specific match might come later
      }
    }
  }

  if (matchNode) {
    matchNode.findings.push(finding);
    addToFindingGroup(matchNode, finding);
    matchNode.maxSeverity = maxSeverity(matchNode.maxSeverity, finding.severity);
    if (typeof updateNodeSeverity === 'function') updateNodeSeverity(matchNode);
  }
  // Orphaned findings will be adopted in adoptOrphanedFindings() at scan:complete

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

// ---- Orphaned Finding Adoption ----
// After scan completes, findings that didn't match any recon node get grouped
// into synthetic nodes by directory, placed in the appropriate lane.
// Groups at a depth that keeps each lane under ~12 nodes for readability.

function adoptOrphanedFindings() {
  // Collect findings that aren't attached to any node
  var attachedIds = {};
  state.nodes.forEach(function(n) {
    n.findings.forEach(function(f) { attachedIds[f.id] = true; });
  });

  var orphans = state.findings.filter(function(f) { return !attachedIds[f.id]; });
  if (orphans.length === 0) return;

  var projectPath = state.projectName || '';

  // Strip project path prefix for grouping
  function relPath(file) {
    var f = file || '';
    if (projectPath && f.indexOf(projectPath) === 0) {
      f = f.substring(projectPath.length);
    }
    if (f.charAt(0) === '/') f = f.substring(1);
    return f;
  }

  // Get the directory at a given depth from a relative path
  // depth 1: "apps" | depth 2: "apps/dashboard" | depth 3: "apps/dashboard/src"
  function dirAtDepth(rel, depth) {
    var parts = rel.split('/');
    // Remove the filename (last segment)
    parts = parts.slice(0, -1);
    if (parts.length === 0) return '(root)';
    if (parts.length <= depth) return parts.join('/');
    return parts.slice(0, depth).join('/');
  }

  // Group orphans by lane first, then find optimal grouping depth per lane
  var byLane = {};
  orphans.forEach(function(f) {
    var lane = classifyFindingLane(f);
    if (!byLane[lane]) byLane[lane] = [];
    byLane[lane].push(f);
  });

  var MAX_NODES_PER_LANE = 12;

  Object.keys(byLane).forEach(function(lane) {
    var laneFindings = byLane[lane];

    // Find the minimum depth that gives <= MAX_NODES_PER_LANE groups
    var bestDepth = 2;
    for (var d = 2; d <= 6; d++) {
      var groups = {};
      laneFindings.forEach(function(f) {
        var dir = dirAtDepth(relPath(f.file), d);
        groups[dir] = true;
      });
      if (Object.keys(groups).length <= MAX_NODES_PER_LANE) {
        bestDepth = d;
        break;
      }
    }
    // If even depth 6 is too many, stay at depth 2
    var testGroups = {};
    laneFindings.forEach(function(f) {
      var dir = dirAtDepth(relPath(f.file), bestDepth);
      testGroups[dir] = true;
    });
    if (Object.keys(testGroups).length > MAX_NODES_PER_LANE) {
      bestDepth = 2;
    }

    // Group findings by directory at chosen depth
    var grouped = {};
    laneFindings.forEach(function(f) {
      var dir = dirAtDepth(relPath(f.file), bestDepth);
      if (!grouped[dir]) grouped[dir] = [];
      grouped[dir].push(f);
    });

    // Create a node per directory group
    Object.keys(grouped).forEach(function(dir) {
      var findings = grouped[dir];
      var nodeId = 'dir:' + lane + ':' + dir;

      if (state.nodes.find(function(n) { return n.id === nodeId; })) return;

      // Use the last path segment as label, or the full dir if short
      var parts = dir.split('/');
      var label = parts.length > 1 ? parts[parts.length - 1] : dir;

      var node = {
        id: nodeId,
        lane: lane,
        label: label,
        type: 'synthetic:dir',
        data: { dir: dir, files: findings.map(function(f) { return f.file; }).filter(function(v, i, a) { return a.indexOf(v) === i; }) },
        findings: findings,
        findingGroups: [],
        maxSeverity: null,
      };

      findings.forEach(function(f) {
        addToFindingGroup(node, f);
        node.maxSeverity = maxSeverity(node.maxSeverity, f.severity);
      });

      state.nodes.push(node);
      if (typeof addNode === 'function') addNode(node);
    });
  });
}

// ---- Lane Consolidation ----
// After orphan adoption, any lane with more than MAX_NODES_PER_LANE nodes
// gets collapsed: remove the per-file/per-route nodes, re-group all their
// findings by directory, and create new directory-level nodes.

function consolidateLanes() {
  var projectPath = state.projectName || '';

  function relPath(file) {
    var f = file || '';
    if (projectPath && f.indexOf(projectPath) === 0) f = f.substring(projectPath.length);
    if (f.charAt(0) === '/') f = f.substring(1);
    return f;
  }

  function dirAtDepth(rel, depth) {
    var parts = rel.split('/');
    parts = parts.slice(0, -1);
    if (parts.length === 0) return '(root)';
    if (parts.length <= depth) return parts.join('/');
    return parts.slice(0, depth).join('/');
  }

  var MAX = 12;

  LANES.forEach(function(laneDef) {
    var laneId = laneDef.id;
    var laneNodes = state.nodes.filter(function(n) { return n.lane === laneId; });
    if (laneNodes.length <= MAX) return;

    // Collect all findings from this lane's nodes
    var allFindings = [];
    laneNodes.forEach(function(n) {
      n.findings.forEach(function(f) { allFindings.push(f); });
    });

    // Remove old nodes from state and graph
    var removeIds = {};
    laneNodes.forEach(function(n) { removeIds[n.id] = true; });
    state.nodes = state.nodes.filter(function(n) { return !removeIds[n.id]; });

    // Clear graph lane
    laneNodePositions[laneId] = [];
    var svgEl = laneSvgElements[laneId];
    if (svgEl) d3.select(svgEl).selectAll('.node-group').remove();
    // Also remove from allGraphNodes
    allGraphNodes = allGraphNodes.filter(function(n) { return !removeIds[n.id]; });

    if (allFindings.length === 0) {
      updateLaneStatus(laneId, 0);
      return;
    }

    // Find best grouping depth
    var bestDepth = 2;
    for (var d = 2; d <= 5; d++) {
      var groups = {};
      allFindings.forEach(function(f) { groups[dirAtDepth(relPath(f.file), d)] = true; });
      if (Object.keys(groups).length <= MAX) { bestDepth = d; break; }
    }

    // Group findings
    var grouped = {};
    allFindings.forEach(function(f) {
      var dir = dirAtDepth(relPath(f.file), bestDepth);
      if (!grouped[dir]) grouped[dir] = [];
      grouped[dir].push(f);
    });

    // Create consolidated nodes
    Object.keys(grouped).forEach(function(dir) {
      var findings = grouped[dir];
      var nodeId = 'dir:' + laneId + ':' + dir;
      var parts = dir.split('/');
      var label = parts.length > 1 ? parts[parts.length - 1] : dir;

      var node = {
        id: nodeId,
        lane: laneId,
        label: label,
        type: 'synthetic:dir',
        data: { dir: dir, files: findings.map(function(f) { return f.file; }).filter(function(v, i, a) { return a.indexOf(v) === i; }) },
        findings: findings,
        findingGroups: [],
        maxSeverity: null,
      };

      findings.forEach(function(f) {
        addToFindingGroup(node, f);
        node.maxSeverity = maxSeverity(node.maxSeverity, f.severity);
      });

      state.nodes.push(node);
      if (typeof addNode === 'function') addNode(node);
    });
  });
}

// ---- Mode Switching ----

function transitionToExploreMode() {
  // Adopt orphaned findings into synthetic nodes
  adoptOrphanedFindings();
  // Consolidate any lane that has too many nodes
  consolidateLanes();

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
