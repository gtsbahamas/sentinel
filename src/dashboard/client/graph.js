// src/dashboard/client/graph.js
// D3 rendering for horizontal lane bands + severity-ringed nodes.
// Loaded before sidebar.js and app.js.

// ---- Severity ranking (single source of truth) ----
var SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

var SEV_COLOR = {
  critical: 'var(--critical)',
  high:     'var(--high)',
  medium:   'var(--medium)',
  low:      'var(--low)',
  info:     'var(--info)',
};

var SEV_GLOW = {
  critical: 'var(--critical-glow)',
  high:     'var(--high-glow)',
  medium:   'var(--medium-glow)',
  low:      'var(--low-glow)',
  info:     'var(--info-dim)',
};

var FIXED_COLOR = '#4aba8a';
var FIXED_GLOW = 'rgba(74, 186, 138, 0.18)';

var LANES = [
  { id: 'frontend', label: 'Frontend', statusColor: 'var(--info)' },
  { id: 'api',      label: 'API',      statusColor: 'var(--low)' },
  { id: 'database', label: 'Database', statusColor: 'var(--medium)' },
  { id: 'external', label: 'External', statusColor: 'var(--ink-faint)' },
];

// Track which nodes are in which lane SVG, keyed by lane id
var laneNodePositions = {};  // { laneId: [{ nodeRef, _x, _y }] }
var laneSvgElements = {};    // { laneId: SVGElement }
var allGraphNodes = [];      // references to node objects with _x, _y, _lane, _svg

// ---- Build lane DOM ----
function buildLanes() {
  var container = document.getElementById('lanesContainer');
  container.innerHTML = '';

  LANES.forEach(function(lane) {
    laneNodePositions[lane.id] = [];

    var div = document.createElement('div');
    div.className = 'lane';
    div.dataset.lane = lane.id;
    div.innerHTML =
      '<div class="lane-label-col">' +
        '<span class="lane-name">' + lane.label + '</span>' +
        '<span class="lane-status" id="lane-status-' + lane.id + '">' +
          '<span class="lane-status-dot" style="background:' + lane.statusColor + '"></span>' +
          '<span class="lane-status-text">0 items</span>' +
        '</span>' +
      '</div>' +
      '<div class="lane-bg"></div>' +
      '<div class="lane-scroll" id="scroll-' + lane.id + '">' +
        '<svg class="lane-svg" id="svg-' + lane.id + '" overflow="visible"></svg>' +
      '</div>';
    container.appendChild(div);

    laneSvgElements[lane.id] = document.getElementById('svg-' + lane.id);
  });
}

// ---- Lane status update ----
function updateLaneStatus(laneId, count) {
  var textEl = document.querySelector('#lane-status-' + laneId + ' .lane-status-text');
  if (textEl) {
    textEl.textContent = count + ' item' + (count !== 1 ? 's' : '');
  }
}

// ---- Minimum spacing per node (px) ----
var NODE_SPACING = 60;

// ---- Ensure SVG is wide enough for all nodes ----
function ensureSvgWidth(laneId) {
  var svgEl = laneSvgElements[laneId];
  if (!svgEl) return;
  var scrollEl = document.getElementById('scroll-' + laneId);
  var containerWidth = scrollEl ? scrollEl.clientWidth : svgEl.parentElement.clientWidth;
  var laneNodes = laneNodePositions[laneId];
  var neededWidth = (laneNodes.length + 1) * NODE_SPACING;
  var finalWidth = Math.max(containerWidth, neededWidth);
  svgEl.style.width = finalWidth + 'px';
  svgEl.style.minWidth = finalWidth + 'px';
}

// ---- Add a single node incrementally ----
function addNode(node) {
  var laneId = node.lane;
  var svgEl = laneSvgElements[laneId];
  if (!svgEl) return;

  var laneNodes = laneNodePositions[laneId];
  laneNodes.push(node);

  ensureSvgWidth(laneId);

  var height = svgEl.clientHeight;

  // Recalculate positions for all nodes in this lane
  var spacing = Math.max(NODE_SPACING, svgEl.clientWidth / (laneNodes.length + 1));
  laneNodes.forEach(function(n, i) {
    n._x = spacing * (i + 1);
    n._y = height / 2;
    n._lane = laneId;
  });

  allGraphNodes.push(node);

  // Update lane status
  updateLaneStatus(laneId, laneNodes.length);

  // Redraw all nodes in this lane (repositions existing ones too)
  redrawLane(laneId);
}

// ---- Redraw all nodes in a single lane ----
function redrawLane(laneId) {
  var svgEl = laneSvgElements[laneId];
  if (!svgEl) return;

  var svg = d3.select(svgEl);
  var laneNodes = laneNodePositions[laneId];
  var r = 20;

  // Determine the selected node (from app.js state)
  var selId = (typeof state !== 'undefined' && state.selectedNodeId) ? state.selectedNodeId : null;

  // Get active filters
  var filters = (typeof state !== 'undefined' && state.activeFilters) ? state.activeFilters : null;

  // Remove old nodes
  svg.selectAll('.node-group').remove();

  laneNodes.forEach(function(node) {
    var sev = node.maxSeverity || 'info';
    var color = SEV_COLOR[sev] || SEV_COLOR.info;
    var glowColor = SEV_GLOW[sev] || SEV_GLOW.info;

    // Compute fix ratio for converge mode
    var totalFindings = node.findings ? node.findings.length : 0;
    var fixedFindings = 0;
    if (node.findings) {
      for (var fi = 0; fi < node.findings.length; fi++) {
        if (node.findings[fi].fixStatus === 'fixed') fixedFindings++;
      }
    }
    var fixRatio = totalFindings > 0 ? fixedFindings / totalFindings : 0;

    // Override colors for fixed nodes
    if (fixRatio === 1 && totalFindings > 0) {
      color = FIXED_COLOR;
      glowColor = FIXED_GLOW;
    }

    var isSelected = selId && selId === node.id;
    var isFaded = selId && selId !== node.id;
    var isFiltered = filters && !filters.has(sev) && sev !== 'info';

    var cls = 'node-group';
    if (isFaded) cls += ' faded';
    if (isSelected) cls += ' selected';

    var g = svg.append('g')
      .attr('class', cls)
      .attr('id', 'node-' + node.id.replace(/[^a-zA-Z0-9_-]/g, '_'))
      .attr('transform', 'translate(' + node._x + ', ' + node._y + ')')
      .style('opacity', isFiltered ? 0.12 : 1)
      .on('click', function() {
        if (typeof onNodeClick === 'function') onNodeClick(node);
      });

    // Glow ring when selected
    if (isSelected) {
      g.append('circle')
        .attr('r', r + 8)
        .attr('fill', glowColor)
        .attr('stroke', 'none');
    }

    // Outer ring
    g.append('circle')
      .attr('class', 'node-ring')
      .attr('r', r + 3)
      .attr('stroke', color)
      .attr('opacity', isSelected ? 0.6 : 0.25);

    // Fix progress arc (partial fix indicator)
    if (fixRatio > 0 && fixRatio < 1) {
      var arcR = r + 3;
      var arc = d3.arc()
        .innerRadius(arcR - 1.5)
        .outerRadius(arcR + 1.5)
        .startAngle(0)
        .endAngle(fixRatio * 2 * Math.PI);
      g.append('path')
        .attr('d', arc)
        .attr('fill', FIXED_COLOR)
        .attr('opacity', 0.8);
    }

    // Inner circle
    g.append('circle')
      .attr('class', 'node-circle')
      .attr('r', r)
      .attr('fill', isSelected ? (color.replace(')', ', 0.13)').replace('var(', 'rgba(').replace('--', '')) : 'var(--surface-raised)')
      .attr('stroke', color)
      .attr('stroke-width', isSelected ? 2 : 1.5);

    // For selected nodes, use a simpler fill approach
    if (isSelected) {
      g.select('.node-circle').attr('fill', 'var(--surface-hover)');
    }

    // Count text (top line: instance total)
    var groupCount = node.findingGroups ? node.findingGroups.length : 0;
    var instanceCount = 0;
    if (node.findingGroups) {
      node.findingGroups.forEach(function(fg) {
        instanceCount += fg.instances.length;
      });
    }

    if (fixRatio === 1 && totalFindings > 0) {
      // Fully fixed: show checkmark
      g.append('text')
        .attr('class', 'node-count')
        .attr('y', 2)
        .attr('fill', FIXED_COLOR)
        .attr('font-size', '16px')
        .text('\u2713');
    } else if (fixedFindings > 0) {
      // Partially fixed: show ratio
      g.append('text')
        .attr('class', 'node-count')
        .attr('y', -3)
        .attr('fill', color)
        .text(fixedFindings + '/' + totalFindings);

      g.append('text')
        .attr('y', 8)
        .attr('text-anchor', 'middle')
        .attr('font-size', '8px')
        .attr('fill', FIXED_COLOR)
        .attr('opacity', 0.7)
        .attr('font-family', 'Inter, sans-serif')
        .attr('font-weight', '600')
        .text('fixed');
    } else if (instanceCount > 0) {
      g.append('text')
        .attr('class', 'node-count')
        .attr('y', -3)
        .attr('fill', color)
        .text(instanceCount);

      // Severity initial letter below count
      var sevText = sev[0].toUpperCase();
      g.append('text')
        .attr('y', 8)
        .attr('text-anchor', 'middle')
        .attr('font-size', '8px')
        .attr('fill', color)
        .attr('opacity', 0.7)
        .attr('font-family', 'Inter, sans-serif')
        .attr('font-weight', '600')
        .text(sevText);
    }

    // Label below node
    var label = node.label || node.id;
    if (label.length > 14) label = label.slice(0, 12) + '..';
    g.append('text')
      .attr('class', 'node-label')
      .attr('y', r + 14)
      .text(label);
  });
}

// ---- Update severity on a node (called when findings arrive) ----
function updateNodeSeverity(node) {
  if (node._lane) {
    redrawLane(node._lane);
  }
}

// ---- Add edge between nodes (draw dashed line across lanes if needed) ----
function addEdge(edgeData) {
  // Find source and target nodes
  var source = allGraphNodes.find(function(n) { return n.id === edgeData.source; });
  var target = allGraphNodes.find(function(n) { return n.id === edgeData.target; });
  if (!source || !target) return;

  // Only draw within-lane edges for now (cross-lane requires overlay SVG)
  if (source._lane === target._lane) {
    var svg = d3.select(laneSvgElements[source._lane]);
    svg.insert('line', '.node-group')
      .attr('class', 'edge')
      .attr('x1', source._x)
      .attr('y1', source._y)
      .attr('x2', target._x)
      .attr('y2', target._y)
      .attr('stroke', 'var(--ink-faint)');
  }
}

// ---- Redraw all lanes (e.g., on selection change or filter change) ----
function redrawAllLanes() {
  LANES.forEach(function(lane) {
    var svgEl = laneSvgElements[lane.id];
    if (!svgEl) return;
    var laneNodes = laneNodePositions[lane.id];
    if (!laneNodes.length) return;

    ensureSvgWidth(lane.id);

    var height = svgEl.clientHeight;
    var spacing = Math.max(NODE_SPACING, svgEl.clientWidth / (laneNodes.length + 1));
    laneNodes.forEach(function(n, i) {
      n._x = spacing * (i + 1);
      n._y = height / 2;
    });

    redrawLane(lane.id);
  });
}

// ---- Apply severity filter (toggle visibility) ----
function applySeverityFilter() {
  redrawAllLanes();
}

// ---- Resize handler ----
var graphResizeTimer;
window.addEventListener('resize', function() {
  clearTimeout(graphResizeTimer);
  graphResizeTimer = setTimeout(function() {
    redrawAllLanes();
  }, 100);
});
