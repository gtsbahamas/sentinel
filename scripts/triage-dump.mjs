// Emit a triage-ready summary of a scan result: findings grouped by file,
// sorted by severity, with reasoning included. Used to drive the human
// review pass where each finding is graded for realness.
//
// Usage: npx tsx scripts/triage-dump.mjs <result.json>

import { readFileSync, writeFileSync } from "fs";

const path = process.argv[2];
if (!path) {
  console.error("Usage: npx tsx scripts/triage-dump.mjs <result.json>");
  process.exit(1);
}

const raw = JSON.parse(readFileSync(path, "utf8"));
const ai = raw.findings.filter((f) => f.layer === "ai");

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
function sevRank(s) {
  return SEV_ORDER.indexOf(s);
}

// Group by file
const byFile = new Map();
for (const f of ai) {
  const file = f.evidence[0]?.file ?? "";
  if (!byFile.has(file)) byFile.set(file, []);
  byFile.get(file).push(f);
}
// Sort files by worst severity, then finding count
const ranked = [...byFile.entries()].sort((a, b) => {
  const worstA = Math.min(...a[1].map((f) => sevRank(f.severity)));
  const worstB = Math.min(...b[1].map((f) => sevRank(f.severity)));
  if (worstA !== worstB) return worstA - worstB;
  return b[1].length - a[1].length;
});

let out = `# Skutt Triage — V2 scan (${ai.length} findings)\n\n`;
out += `Grading scale per finding:\n`;
out += `- **REAL** — genuine exploit, severity appropriate\n`;
out += `- **REAL-UNDER** — genuine exploit, severity understated (upgrade)\n`;
out += `- **REAL-OVER** — genuine but severity inflated (downgrade)\n`;
out += `- **FALSE-POSITIVE** — AI misread code (auth via middleware, etc.)\n`;
out += `- **UNREACHABLE** — code exists but no route reaches it in prod\n`;
out += `- **DUPLICATE** — dedup missed a sibling finding\n`;
out += `- **ALREADY-FIXED** — addressed in uncommitted tree or another branch\n\n`;
out += `---\n\n`;

let idx = 0;
for (const [file, findings] of ranked) {
  findings.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const rel = file.replace(/.*\/skutt\//, "");
  out += `## ${rel}\n\n`;
  for (const f of findings) {
    idx++;
    const reasoning = f.evidence[0]?.context?.reasoning ?? "";
    out += `### #${idx} [${f.severity}/${f.confidence}] [${f.domain}] ${f.title}\n\n`;
    out += `**Description:** ${f.description}\n\n`;
    out += `**Reasoning:** ${reasoning}\n\n`;
    out += `**Evidence lines:** ${f.evidence.map((e) => e.line ?? "?").join(", ")}\n\n`;
    out += `**Remediation (AI draft):** ${f.remediation}\n\n`;
    out += `**Grade:** _(pending)_\n\n`;
    out += `---\n\n`;
  }
}

const outPath = "/tmp/skutt-scan/triage.md";
writeFileSync(outPath, out);
console.log(`Wrote ${idx} findings grouped by file → ${outPath}`);
console.log(`File count: ${ranked.length}`);
console.log(`By severity: ` + JSON.stringify(
  ai.reduce((d, f) => ({ ...d, [f.severity]: (d[f.severity] ?? 0) + 1 }), {}),
));
