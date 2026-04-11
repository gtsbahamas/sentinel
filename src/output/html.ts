import type { Finding, ProjectModel, Severity, SecurityDomain } from "../model/types.js";
import { compareSeverity } from "../model/severity.js";
import type { LayerTiming } from "./json.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const DOMAINS: SecurityDomain[] = [
  "secrets-exposure",
  "input-injection",
  "auth-access-control",
  "file-upload",
  "api-security",
  "cryptography",
  "supply-chain",
  "infrastructure",
  "business-logic",
  "logging-monitoring",
];

const SEVERITY_COLOR: Record<Severity, { bg: string; fg: string; border: string }> = {
  critical: { bg: "#dc2626", fg: "#ffffff", border: "#991b1b" },
  high: { bg: "#ea580c", fg: "#ffffff", border: "#9a3412" },
  medium: { bg: "#f59e0b", fg: "#1c1917", border: "#b45309" },
  low: { bg: "#3b82f6", fg: "#ffffff", border: "#1d4ed8" },
  info: { bg: "#64748b", fg: "#ffffff", border: "#334155" },
};

function escape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function severityBadge(sev: Severity): string {
  const colors = SEVERITY_COLOR[sev];
  return `<span class="sev-badge" style="background:${colors.bg};color:${colors.fg};border-color:${colors.border};">${sev.toUpperCase()}</span>`;
}

function renderFinding(f: Finding): string {
  const evidence = f.evidence
    .map(
      (ev) => `<li><code>${escape(ev.file)}${ev.line !== undefined ? `:${ev.line}` : ""}</code>${
        ev.snippet ? `<pre class="snippet">${escape(ev.snippet)}</pre>` : ""
      }</li>`,
    )
    .join("");
  const refs = f.references.length
    ? `<div class="refs">${f.references.map((r) => `<span class="ref">${escape(r)}</span>`).join("")}</div>`
    : "";
  return `
    <details class="finding sev-${f.severity}">
      <summary>
        ${severityBadge(f.severity)}
        <code class="rule-id">${escape(f.id.split("-").slice(0, 2).join("-"))}</code>
        <span class="title">${escape(f.title)}</span>
        <span class="domain-tag">${escape(f.domain)}</span>
      </summary>
      <div class="body">
        <p class="description">${escape(f.description)}</p>
        <h4>Evidence</h4>
        <ul class="evidence">${evidence}</ul>
        <h4>Remediation</h4>
        <p class="remediation">${escape(f.remediation)}</p>
        ${refs}
      </div>
    </details>
  `;
}

export function formatHtml(
  model: ProjectModel,
  findings: Finding[],
  timing: LayerTiming,
): string {
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;

  const byDomain = new Map<SecurityDomain, Finding[]>();
  for (const f of findings) {
    if (!byDomain.has(f.domain)) byDomain.set(f.domain, []);
    byDomain.get(f.domain)!.push(f);
  }
  for (const list of byDomain.values()) {
    list.sort((a, b) => compareSeverity(a.severity, b.severity));
  }

  const domainSections = DOMAINS
    .filter((d) => byDomain.has(d))
    .map((domain) => {
      const list = byDomain.get(domain)!;
      const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of list) counts[f.severity]++;
      const countBadges = SEVERITY_ORDER
        .filter((s) => counts[s] > 0)
        .map((s) => `<span class="count-badge" style="background:${SEVERITY_COLOR[s].bg};color:${SEVERITY_COLOR[s].fg};">${counts[s]} ${s}</span>`)
        .join("");
      return `
        <section class="domain-section" id="domain-${domain}">
          <h2>${escape(domain)} <span class="counts">${countBadges}</span></h2>
          <div class="findings-list">
            ${list.map(renderFinding).join("")}
          </div>
        </section>
      `;
    })
    .join("");

  const summaryCards = SEVERITY_ORDER
    .map((sev) => {
      const colors = SEVERITY_COLOR[sev];
      return `
        <div class="summary-card" style="border-left:4px solid ${colors.bg};">
          <div class="card-value" style="color:${colors.bg};">${summary[sev]}</div>
          <div class="card-label">${sev}</div>
        </div>
      `;
    })
    .join("");

  const domainRows = DOMAINS
    .map((domain) => {
      const list = byDomain.get(domain) ?? [];
      if (list.length === 0) return "";
      const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of list) counts[f.severity]++;
      return `
        <tr>
          <td><a href="#domain-${domain}">${escape(domain)}</a></td>
          <td class="n">${counts.critical}</td>
          <td class="n">${counts.high}</td>
          <td class="n">${counts.medium}</td>
          <td class="n">${counts.low}</td>
          <td class="n">${counts.info}</td>
          <td class="n total">${list.length}</td>
        </tr>
      `;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel — ${escape(model.meta.name)}</title>
<style>
  :root {
    --bg: #0f172a;
    --panel: #1e293b;
    --panel-2: #0b1220;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --border: #334155;
    --accent: #22d3ee;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text); font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
  .container { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 32px; }
  header h1 { margin: 0 0 8px; font-size: 28px; letter-spacing: -0.02em; }
  header .meta { color: var(--muted); font-size: 13px; }
  header .meta span { margin-right: 16px; }
  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
  .summary-card { background: var(--panel); border-radius: 6px; padding: 16px; }
  .card-value { font-size: 32px; font-weight: 700; line-height: 1; }
  .card-label { text-transform: uppercase; font-size: 11px; color: var(--muted); letter-spacing: 0.08em; margin-top: 6px; }
  .domain-table { width: 100%; border-collapse: collapse; margin-bottom: 32px; background: var(--panel); border-radius: 6px; overflow: hidden; }
  .domain-table th, .domain-table td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  .domain-table th { font-size: 11px; text-transform: uppercase; color: var(--muted); letter-spacing: 0.05em; background: var(--panel-2); }
  .domain-table td.n { text-align: right; font-variant-numeric: tabular-nums; }
  .domain-table td.total { font-weight: 600; }
  .domain-table a { color: var(--accent); text-decoration: none; }
  .domain-table a:hover { text-decoration: underline; }
  .domain-section { margin-bottom: 32px; }
  .domain-section h2 { font-size: 18px; letter-spacing: -0.01em; margin: 0 0 12px; display: flex; align-items: center; gap: 12px; }
  .counts { display: inline-flex; gap: 6px; }
  .count-badge { padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
  .findings-list { display: flex; flex-direction: column; gap: 8px; }
  .finding { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  .finding summary { padding: 12px 16px; cursor: pointer; list-style: none; display: flex; align-items: center; gap: 10px; }
  .finding summary::-webkit-details-marker { display: none; }
  .finding[open] summary { border-bottom: 1px solid var(--border); background: var(--panel-2); }
  .sev-badge { padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; letter-spacing: 0.06em; border: 1px solid; flex-shrink: 0; }
  .rule-id { background: var(--panel-2); padding: 2px 6px; border-radius: 4px; color: var(--accent); font-size: 12px; flex-shrink: 0; }
  .title { flex: 1; color: var(--text); }
  .domain-tag { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
  .body { padding: 16px; }
  .body h4 { margin: 16px 0 6px; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .body h4:first-of-type { margin-top: 0; }
  .description, .remediation { margin: 0; color: var(--text); }
  .evidence { margin: 0; padding: 0; list-style: none; }
  .evidence li { padding: 6px 0; border-bottom: 1px dashed var(--border); }
  .evidence li:last-child { border-bottom: none; }
  .evidence code { color: var(--accent); font-size: 12px; }
  .snippet { margin: 6px 0 0; padding: 8px 10px; background: var(--panel-2); border-radius: 4px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .refs { margin-top: 12px; display: flex; gap: 6px; flex-wrap: wrap; }
  .ref { padding: 2px 8px; background: var(--panel-2); border-radius: 10px; font-size: 11px; color: var(--muted); }
  footer { color: var(--muted); font-size: 12px; text-align: center; margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border); }
</style>
</head>
<body>
<div class="container">
<header>
  <h1>Sentinel Security Assessment</h1>
  <div class="meta">
    <span><strong>Project:</strong> ${escape(model.meta.name)}</span>
    <span><strong>Stack:</strong> ${escape(model.meta.stack)}</span>
    <span><strong>Framework:</strong> ${escape(model.meta.framework)}</span>
    <span><strong>Scanned:</strong> ${new Date().toISOString()}</span>
  </div>
  <div class="meta" style="margin-top:6px;">
    <span>Recon: ${timing.recon_ms}ms</span>
    <span>Rules: ${timing.rules_ms}ms</span>
    <span>Endpoints: ${model.endpoints.length}</span>
    <span>Routes: ${model.routes.length}</span>
    <span>Dependencies: ${model.dependencies.length}</span>
  </div>
</header>

<h2 style="margin-top:0;">Summary</h2>
<div class="summary-grid">
  ${summaryCards}
</div>

<table class="domain-table">
  <thead>
    <tr>
      <th>Domain</th>
      <th class="n">Crit</th>
      <th class="n">High</th>
      <th class="n">Medium</th>
      <th class="n">Low</th>
      <th class="n">Info</th>
      <th class="n">Total</th>
    </tr>
  </thead>
  <tbody>
    ${domainRows || '<tr><td colspan="7" style="text-align:center;color:var(--muted);">No findings</td></tr>'}
  </tbody>
</table>

${domainSections}

<footer>
  Sentinel v0.1.0 — ${findings.length} findings across ${byDomain.size} domains
</footer>
</div>
</body>
</html>`;
}
