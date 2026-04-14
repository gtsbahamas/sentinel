// src/dashboard/client/sidebar.js
// Detail panel rendering: summary view, node detail view, vuln cards.
// Loaded after graph.js, before app.js.

// ---- Utility ----
function escapeHtml(str) {
  if (!str) return '';
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---- Scan status display ----
function updateScanStatus(text) {
  var el = document.getElementById('scanStatusText');
  if (el) el.textContent = text;
}

function setScanDotClass(cls) {
  var dot = document.getElementById('scanDot');
  if (!dot) return;
  dot.className = 'scan-dot';
  if (cls) dot.classList.add(cls);
}

// ---- Scan progress log (shown during scanning) ----
function addScanLogEntry(level, message) {
  var container = document.getElementById('scanProgressView');
  if (!container) return;

  var entry = document.createElement('div');
  entry.className = 'scan-log-entry' + (level === 'warn' ? ' warn' : '') + (level === 'error' ? ' error' : '');

  var time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  entry.innerHTML = '<span class="log-time">' + time + '</span> ' + escapeHtml(message);

  container.appendChild(entry);

  // Auto-scroll the detail panel
  var scroll = document.getElementById('detailScroll');
  if (scroll) scroll.scrollTop = scroll.scrollHeight;
}

// ---- Converge tracker (shown during converge mode) ----
function renderConvergeTracker() {
  var tracker = document.getElementById('convergeTracker');
  if (!tracker) return;
  if (typeof state === 'undefined' || !state.isConverge) {
    tracker.style.display = 'none';
    return;
  }

  tracker.style.display = 'block';

  var round = state.currentRound || 0;
  var max = state.maxRounds || 5;
  var summaries = state.roundSummaries || [];
  var initial = summaries.length > 0 ? summaries[0].findingsBefore : 0;
  var totalFixed = 0;
  var remaining = initial;
  for (var i = 0; i < summaries.length; i++) {
    totalFixed += summaries[i].fixed;
    remaining = summaries[i].findingsAfter;
  }

  var pct = initial > 0 ? Math.round((totalFixed / initial) * 100) : 0;

  // Build stepper dots
  var dots = '';
  for (var d = 1; d <= max; d++) {
    var cls = 'converge-dot';
    if (d < round) cls += ' done';
    else if (d === round) cls += ' current';
    dots += '<span class="' + cls + '" data-round="' + d + '">' + d + '</span>';
    if (d < max) dots += '<span class="converge-line' + (d < round ? ' done' : '') + '"></span>';
  }

  // Progress bar
  var barPct = initial > 0 ? Math.min(100, Math.round((totalFixed / initial) * 100)) : 0;

  tracker.innerHTML =
    '<div class="converge-header">' +
      '<span class="converge-label">CONVERGE</span>' +
      '<span class="converge-round">Round ' + round + ' of ' + max + '</span>' +
    '</div>' +
    '<div class="converge-bar-container">' +
      '<div class="converge-bar-fill" style="width:' + barPct + '%"></div>' +
    '</div>' +
    '<div class="converge-stats">' +
      (initial > 0 ? initial + ' → ' + remaining + ' findings (' + pct + '% reduced)' : 'Waiting...') +
    '</div>' +
    '<div class="converge-stepper">' + dots + '</div>';
}

// ---- Summary view (shown after scan:complete) ----
function renderSummary() {
  var content = document.getElementById('detailContent');
  var scroll = document.getElementById('detailScroll');

  // Build global finding groups across all nodes
  var globalGroups = {};
  var totals = { critical: 0, high: 0, medium: 0, low: 0 };

  if (typeof state === 'undefined') return;

  state.nodes.forEach(function(node) {
    if (!node.findingGroups) return;
    node.findingGroups.forEach(function(fg) {
      var key = fg.title;
      if (!globalGroups[key]) {
        globalGroups[key] = {
          title: fg.title,
          severity: fg.severity,
          totalInstances: 0,
          nodeIds: [],
        };
      }
      // Use max severity
      if ((SEVERITY_RANK[fg.severity] || 0) > (SEVERITY_RANK[globalGroups[key].severity] || 0)) {
        globalGroups[key].severity = fg.severity;
      }
      globalGroups[key].totalInstances += fg.instances.length;
      if (globalGroups[key].nodeIds.indexOf(node.id) === -1) {
        globalGroups[key].nodeIds.push(node.id);
      }
    });
  });

  // Count totals from raw findings
  state.findings.forEach(function(f) {
    if (totals[f.severity] !== undefined) {
      totals[f.severity]++;
    }
  });

  var sortedGroups = Object.values(globalGroups).sort(function(a, b) {
    return (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
  });

  var totalClasses = sortedGroups.length;
  var totalInstances = totals.critical + totals.high + totals.medium + totals.low;

  var vulnRows = sortedGroups.map(function(g) {
    return '<div class="vuln-summary-row" data-vuln-title="' + escapeHtml(g.title) + '" onclick="showVulnFromSummary(\'' + escapeHtml(g.title).replace(/'/g, "\\'") + '\')">' +
      '<span class="sev-tag ' + g.severity + '">' + g.severity + '</span>' +
      '<span class="vuln-summary-name">' + escapeHtml(g.title) + '</span>' +
      '<span class="vuln-summary-instances">' + g.totalInstances + ' instance' + (g.totalInstances !== 1 ? 's' : '') + '</span>' +
    '</div>';
  }).join('');

  // Build convergence results section if in converge mode
  var convergeHtml = '';
  if (typeof state !== 'undefined' && state.isConverge && state.roundSummaries && state.roundSummaries.length > 0) {
    var rs = state.roundSummaries;
    var initial = rs[0].findingsBefore;
    var totalFixed = 0;
    for (var ci = 0; ci < rs.length; ci++) totalFixed += rs[ci].fixed;
    var remaining = rs[rs.length - 1].findingsAfter;
    var pctReduced = initial > 0 ? ((totalFixed / initial) * 100).toFixed(1) : '0';

    var stopLabels = {
      'zero-findings': 'Clean — zero findings remain',
      'no-fixes': 'Converged — remaining findings not auto-fixable',
      'not-decreasing': 'Stopped — finding count not decreasing',
      'max-rounds': 'Max rounds reached'
    };
    var stopLabel = (state.stopReason && stopLabels[state.stopReason]) || '';

    convergeHtml =
      '<div class="converge-results">' +
        '<div class="converge-results-title">Convergence Results</div>' +
        '<div class="converge-results-grid">' +
          '<div class="converge-stat"><div class="converge-stat-value">' + rs.length + '</div><div class="converge-stat-label">Rounds</div></div>' +
          '<div class="converge-stat"><div class="converge-stat-value">' + totalFixed + '</div><div class="converge-stat-label">Total fixed</div></div>' +
          '<div class="converge-stat"><div class="converge-stat-value">' + pctReduced + '%</div><div class="converge-stat-label">Reduction</div></div>' +
          '<div class="converge-stat"><div class="converge-stat-value">' + remaining + '</div><div class="converge-stat-label">Remaining</div></div>' +
        '</div>' +
        (stopLabel ? '<div class="converge-stop-reason">' + stopLabel + '</div>' : '') +
      '</div>';
  }

  // Build delta annotations for metric cards (converge mode)
  var deltas = { critical: 0, high: 0, medium: 0, low: 0 };
  if (typeof state !== 'undefined' && state.isConverge) {
    state.findings.forEach(function(f) {
      if (f.fixStatus === 'fixed' && deltas[f.severity] !== undefined) {
        deltas[f.severity]++;
      }
    });
  }

  function deltaHtml(sev) {
    if (!state.isConverge || deltas[sev] === 0) return '';
    return '<div class="metric-delta">-' + deltas[sev] + ' fixed</div>';
  }

  content.innerHTML =
    '<div class="summary-view">' +
      convergeHtml +
      '<div class="summary-metrics">' +
        '<div class="metric-card critical"><div class="metric-value">' + totals.critical + '</div><div class="metric-label">Critical instances</div>' + deltaHtml('critical') + '</div>' +
        '<div class="metric-card high"><div class="metric-value">' + totals.high + '</div><div class="metric-label">High severity</div>' + deltaHtml('high') + '</div>' +
        '<div class="metric-card medium"><div class="metric-value">' + totals.medium + '</div><div class="metric-label">Medium severity</div>' + deltaHtml('medium') + '</div>' +
        '<div class="metric-card low"><div class="metric-value">' + totals.low + '</div><div class="metric-label">Low severity</div>' + deltaHtml('low') + '</div>' +
      '</div>' +
      '<div>' +
        '<div class="summary-section-title">' + totalClasses + ' vulnerability classes / ' + totalInstances + ' instances</div>' +
        '<div class="vuln-list">' + vulnRows + '</div>' +
      '</div>' +
      '<div class="click-hint">' +
        '<svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="4.5" stroke="currentColor" stroke-width="1"/><path d="M6 4v4M4 6h4" stroke="currentColor" stroke-width="1" stroke-linecap="round"/></svg>' +
        'Click any node in the graph to see its specific findings' +
      '</div>' +
    '</div>';

  if (scroll) scroll.scrollTop = 0;
}

// ---- Show vuln from summary click (find a node with that vuln and select it) ----
function showVulnFromSummary(vulnTitle) {
  if (typeof state === 'undefined') return;
  var node = state.nodes.find(function(n) {
    return n.findingGroups && n.findingGroups.some(function(fg) { return fg.title === vulnTitle; });
  });
  if (node && typeof onNodeClick === 'function') {
    onNodeClick(node);
  }
}

// ---- Node detail view ----
function renderNodeDetail(node) {
  var content = document.getElementById('detailContent');
  var scroll = document.getElementById('detailScroll');

  var groups = node.findingGroups || [];
  var totalInstances = 0;
  groups.forEach(function(g) { totalInstances += g.instances.length; });

  var sev = node.maxSeverity || 'info';
  var color = SEV_COLOR[sev] || SEV_COLOR.info;

  // Icon: use lane-based letter
  var laneIcons = { frontend: 'FE', api: 'API', database: 'DB', external: 'EXT' };
  var iconText = laneIcons[node.lane] || '?';

  // Description from data
  var desc = '';
  if (node.data) {
    if (node.data.method && node.data.path) desc = node.data.method.toUpperCase() + ' ' + node.data.path;
    else if (node.data.dir) desc = node.data.dir + ' (' + (node.data.files ? node.data.files.length : 0) + ' files)';
    else if (node.data.file) desc = node.data.file;
    else if (node.data.type) desc = node.data.type;
  }

  var vulnCards = groups.map(function(g) {
    var cardId = 'vcard-' + g.title.replace(/[^a-zA-Z0-9]/g, '_');

    var locationsHtml = g.instances.map(function(inst) {
      return '<div class="location-item">' +
        '<span class="location-file">' + escapeHtml(inst.file) + '</span>' +
        (inst.line ? '<span class="location-line">L' + inst.line + '</span>' : '') +
      '</div>';
    }).join('');

    var impactHtml = '';
    if (g.impact) {
      impactHtml = '<div class="impact-section">' +
        '<div class="impact-label">What happens if this is exploited</div>' +
        '<div class="impact-text">' + escapeHtml(g.impact) + '</div>' +
      '</div>';
    }

    var remediationHtml = '';
    if (g.remediation) {
      var remId = 'rem-' + cardId;
      remediationHtml = '<div class="collapsible-section" id="' + remId + '">' +
        '<div class="collapsible-toggle" onclick="toggleSection(\'' + remId + '\')">' +
          '<svg class="collapsible-icon" width="8" height="12" viewBox="0 0 8 12" fill="none"><path d="M2 2L6 6L2 10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
          'Remediation' +
        '</div>' +
        '<div class="collapsible-content">' +
          '<div class="remediation-text">' + escapeHtml(g.remediation) + '</div>' +
        '</div>' +
      '</div>';
    }

    var locId = 'loc-' + cardId;
    var locationsSection = '<div class="collapsible-section" id="' + locId + '">' +
      '<div class="collapsible-toggle" onclick="toggleSection(\'' + locId + '\')">' +
        '<svg class="collapsible-icon" width="8" height="12" viewBox="0 0 8 12" fill="none"><path d="M2 2L6 6L2 10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
        'Locations (' + g.instances.length + ')' +
      '</div>' +
      '<div class="collapsible-content">' +
        '<div class="location-list">' + locationsHtml + '</div>' +
      '</div>' +
    '</div>';

    return '<div class="vuln-card" id="' + cardId + '">' +
      '<div class="vuln-card-header" onclick="toggleCard(\'' + cardId + '\')">' +
        '<div style="flex:1; min-width:0;">' +
          '<div class="vuln-card-label">Vulnerability</div>' +
          '<div class="vuln-card-title">' + escapeHtml(g.title) + '</div>' +
        '</div>' +
        '<div class="vuln-card-meta">' +
          '<span class="instance-badge">' + g.instances.length + 'x</span>' +
          '<span class="sev-tag ' + g.severity + '">' + g.severity + '</span>' +
          '<svg class="chevron" width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M4.5 3L7.5 6L4.5 9" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
        '</div>' +
      '</div>' +
      '<div class="vuln-card-body">' +
        impactHtml +
        remediationHtml +
        locationsSection +
      '</div>' +
    '</div>';
  }).join('');

  var label = node.label || node.id;

  content.innerHTML =
    '<div class="node-detail-view">' +
      '<div class="node-detail-intro">' +
        '<div class="node-detail-icon" style="background:' + color.replace('var(--', 'rgba(').replace(')', ', 0.1)') + '; color:' + color + '">' +
          iconText +
        '</div>' +
        '<div class="node-detail-meta">' +
          '<div class="node-detail-name">' + escapeHtml(label) + '</div>' +
          '<div class="node-detail-desc">' + escapeHtml(desc) + '</div>' +
          '<div class="node-detail-stats">' +
            '<span class="node-stat"><strong>' + groups.length + '</strong> vulnerability class' + (groups.length !== 1 ? 'es' : '') + '</span>' +
            '<span class="node-stat">&#183;</span>' +
            '<span class="node-stat"><strong>' + totalInstances + '</strong> instances</span>' +
            '<span class="node-stat">&#183;</span>' +
            '<span class="sev-tag ' + sev + '" style="font-size:9px; padding:1px 6px;">' + sev + ' risk</span>' +
          '</div>' +
        '</div>' +
      '</div>' +
      vulnCards +
    '</div>';

  // Auto-expand first card
  var firstCard = content.querySelector('.vuln-card');
  if (firstCard) firstCard.classList.add('expanded');

  if (scroll) scroll.scrollTop = 0;
}

// ---- Card toggles ----
function toggleCard(cardId) {
  var card = document.getElementById(cardId);
  if (!card) return;
  card.classList.toggle('expanded');
}

function toggleSection(sectionId) {
  var section = document.getElementById(sectionId);
  if (!section) return;
  section.classList.toggle('open');
}
