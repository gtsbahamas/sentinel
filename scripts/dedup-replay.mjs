// Replay the AI finding dedup on a saved scan result JSON, without rerunning
// the AI layer. Useful after tweaking dedup.ts to measure the impact on real
// data without spending API budget.
//
// Usage:
//   npx tsx scripts/dedup-replay.mjs <path-to-result.json>
//
// The input file is the JSON output of `security-agent scan --ai --format json`.

import { readFileSync } from "fs";
import { dedupAIFindings, classifyIssueTag, normalizeTitle } from "../src/layers/ai/dedup.ts";

const path = process.argv[2];
if (!path) {
  console.error("Usage: npx tsx scripts/dedup-replay.mjs <result.json>");
  process.exit(1);
}

const raw = JSON.parse(readFileSync(path, "utf8"));
const ai = raw.findings.filter((f) => f.layer === "ai");
const nonAi = raw.findings.filter((f) => f.layer !== "ai");

console.log(`Input: ${raw.findings.length} total (${ai.length} AI, ${nonAi.length} non-AI)`);

const result = dedupAIFindings(raw.findings);
const afterAi = result.findings.filter((f) => f.layer === "ai").length;
const reduction = ai.length > 0 ? ((result.collapsedCount / ai.length) * 100).toFixed(1) : "0";

console.log(`After:  ${result.findings.length} total (${afterAi} AI)`);
console.log(`Collapsed: ${result.collapsedCount} (${reduction}% reduction)\n`);

function dist(findings) {
  const d = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) d[f.severity]++;
  return d;
}
console.log("Severity before:", dist(ai));
console.log("Severity after: ", dist(result.findings.filter((f) => f.layer === "ai")));

// Rebuild the groups so we can show what collapsed.
const groups = new Map();
for (const f of ai) {
  const file = f.evidence[0]?.file ?? "";
  const tag = classifyIssueTag(f.title);
  const broad = new Set(["input_validation", "business_logic"]);
  const payload = tag === "unclassified" || broad.has(tag) ? `literal:${normalizeTitle(f.title)}` : tag;
  const key = `${file}|${f.domain}|${payload}`;
  if (!groups.has(key)) groups.set(key, []);
  groups.get(key).push(f);
}
const collapsed = [...groups.entries()]
  .filter(([, arr]) => arr.length > 1)
  .sort((a, b) => b[1].length - a[1].length);

console.log(`\nCollapse buckets: ${collapsed.length}`);
console.log(`Top 10 largest buckets:`);
for (const [key, arr] of collapsed.slice(0, 10)) {
  const [file, domain, tag] = key.split("|");
  const rel = file.replace(/.*\/src\/app\//, "src/app/");
  console.log(`  ${arr.length}x [${domain}][${tag}] ${rel}`);
}
