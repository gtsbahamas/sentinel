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
  document.getElementById("stat-findings").textContent = `${state.stats.classes} classes (${state.stats.findings} instances)`;
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

  const groups = node.findingGroups || [];
  if (groups.length === 0) {
    findingsEl.innerHTML = '<p class="muted">No findings for this node.</p>';
  } else {
    findingsEl.innerHTML = groups.map((g, i) => {
      const instanceCount = g.instances.length;
      const countLabel = instanceCount > 1 ? `<span class="instance-count">${instanceCount} instances</span>` : "";
      const instancesHtml = g.instances.map((inst) =>
        `<div class="instance-row">${escapeHtml(inst.file)}${inst.line ? `:${inst.line}` : ""}</div>`
      ).join("");

      return `
        <div class="finding-group ${g.severity}">
          <div class="finding-group-header" onclick="toggleFindingGroup(this)">
            <span class="finding-group-chevron">&#9654;</span>
            <span class="finding-group-title">${escapeHtml(g.title)}</span>
            ${countLabel}
          </div>
          <div class="finding-group-body collapsed">
            ${g.impact ? `<div class="finding-group-impact">${escapeHtml(g.impact)}</div>` : ""}
            <div class="finding-group-meta">
              <span class="detail-tag ${g.severity}">${g.severity}</span>
              <span class="detail-tag">${escapeHtml(g.domain)}</span>
            </div>
            ${g.remediation ? `<div class="finding-group-remediation"><div class="detail-label">Fix</div>${escapeHtml(g.remediation)}</div>` : ""}
            <div class="finding-group-instances">
              <div class="detail-label">Locations</div>
              ${instancesHtml}
            </div>
          </div>
        </div>
      `;
    }).join("");
  }
}

function toggleFindingGroup(headerEl) {
  const body = headerEl.nextElementSibling;
  const chevron = headerEl.querySelector(".finding-group-chevron");
  body.classList.toggle("collapsed");
  chevron.classList.toggle("expanded");
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
