// src/dashboard/client/sidebar.js

function updateStatusText(text) {
  document.getElementById("scan-status-text").textContent = text;
}

function setStatusClass(cls) {
  const el = document.getElementById("scan-status");
  el.classList.remove("scanning", "complete");
  if (cls) el.classList.add(cls);
}

function updateStatsPanel() {
  document.getElementById("stat-routes").textContent = state.stats.routes;
  document.getElementById("stat-endpoints").textContent = state.stats.endpoints;
  document.getElementById("stat-findings").textContent = state.stats.findings;
  document.getElementById("stat-critical").textContent = state.stats.critical;
  document.getElementById("stat-high").textContent = state.stats.high;
  document.getElementById("stat-medium").textContent = state.stats.medium;
  document.getElementById("stat-low").textContent = state.stats.low;
}

function addLogEntry(level, message) {
  const container = document.getElementById("log-entries");
  const entry = document.createElement("div");
  entry.className = `log-entry ${level}`;

  const time = new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  entry.innerHTML = `<span class="log-time">${time}</span>${escapeHtml(message)}`;

  container.appendChild(entry);
  container.scrollTop = container.scrollHeight;
}

function updateLaneStatus(layerOrLane, statusState, statusText) {
  const laneMap = { recon: null, rules: null, ai: null, frontend: "frontend", api: "api", database: "database", external: "external" };
  const lane = laneMap[layerOrLane] ?? layerOrLane;
  if (!lane) return;

  const header = document.querySelector(`.lane-header[data-lane="${lane}"]`);
  if (!header) return;
  header.setAttribute("data-state", statusState);
  const statusEl = header.querySelector(".lane-status");
  if (statusEl) statusEl.textContent = statusText;
}

function showNodeDetail(node) {
  const titleEl = document.getElementById("node-detail-title");
  const bodyEl = document.getElementById("node-detail-body");
  const findingsEl = document.getElementById("node-findings-list");

  titleEl.textContent = node.id;

  let html = "";
  if (node.data.file) {
    html += `<div class="detail-field"><div class="detail-label">File</div><div class="detail-value">${escapeHtml(node.data.file)}</div></div>`;
  }
  if (node.data.method) {
    html += `<div class="detail-field"><div class="detail-label">Method</div><div class="detail-value">${escapeHtml(node.data.method)}</div></div>`;
  }

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

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
