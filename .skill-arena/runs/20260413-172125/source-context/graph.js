// src/dashboard/client/graph.js

const svg = d3.select("#graph-svg");
const width = () => document.getElementById("graph-area").clientWidth;
const height = () => document.getElementById("graph-area").clientHeight;

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

// Draw lane backgrounds
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

// Force simulation
const simulation = d3.forceSimulation()
  .force("charge", d3.forceManyBody().strength(-80))
  .force("collide", d3.forceCollide().radius(35))
  .force("y", d3.forceY(height() / 2).strength(0.03))
  .on("tick", ticked);

simulation.stop();

const edgeGroup = svg.append("g").attr("class", "edges");
const nodeGroup = svg.append("g").attr("class", "nodes");
const pulseGroup = svg.append("g").attr("class", "pulses");

let simNodes = [];
let simEdges = [];

const NODE_RADIUS = 20;
const RECT_W = 50;
const RECT_H = 28;

function nodeShape(lane) {
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
      if (typeof state !== "undefined" && state.mode === "explore") {
        event.stopPropagation();
        if (typeof selectNode === "function") selectNode(d.id);
        highlightSelected(d.id);
      }
    });

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

    const label = d.id.length > 12 ? d.id.slice(-12) : d.id;
    g.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", shape === "circle" || shape === "diamond" ? NODE_RADIUS + 14 : RECT_H / 2 + 14)
      .attr("font-size", "10px")
      .attr("fill", "#94a3b8")
      .text(label);
  });

  setTimeout(() => { enter.classed("entering", false); }, 400);
}

// Severity colors
const SEVERITY_COLORS = {
  critical: { fill: "#991b1b", stroke: "#ef4444", glow: "rgba(239,68,68,0.4)" },
  high:     { fill: "#7c2d12", stroke: "#f97316", glow: "rgba(249,115,22,0.3)" },
  medium:   { fill: "#78350f", stroke: "#f59e0b", glow: "rgba(245,158,11,0.2)" },
};

function updateNodeSeverity(node) {
  const colors = SEVERITY_COLORS[node.maxSeverity];
  if (!colors) return;

  const g = nodeGroup.selectAll(".node-group").filter((d) => d.id === node.id);

  g.select(".node-shape")
    .transition().duration(400)
    .attr("fill", colors.fill)
    .attr("stroke", colors.stroke);

  let badge = g.select(".badge-group");
  if (badge.empty()) {
    badge = g.append("g").attr("class", "badge-group");
    badge.append("circle").attr("r", 8).attr("cx", NODE_RADIUS - 2).attr("cy", -NODE_RADIUS + 2);
    badge.append("text").attr("class", "node-badge").attr("x", NODE_RADIUS - 2).attr("y", -NODE_RADIUS + 2);
  }
  badge.select("circle").attr("fill", colors.stroke);
  badge.select("text").text(node.findingGroups ? node.findingGroups.length : node.findings.length);

  const pulse = pulseGroup.append("circle")
    .attr("cx", node.x).attr("cy", node.y)
    .attr("r", 0).attr("fill", "none")
    .attr("stroke", colors.stroke).attr("stroke-width", 2).attr("opacity", 0.6);
  pulse.transition().duration(800).attr("r", 40).attr("opacity", 0).remove();
}

// Edges
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

// Selection highlight
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

// Severity filter
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

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

// Tick
function ticked() {
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

// Deselect on empty space
svg.on("click", () => {
  if (typeof state !== "undefined" && state.mode === "explore") {
    if (typeof deselectNode === "function") deselectNode();
    highlightSelected(null);
  }
});

// Resize
window.addEventListener("resize", () => {
  drawLanes();
  simulation.force("y", d3.forceY(height() / 2).strength(0.03));
  simulation.alpha(0.3).restart();
});
