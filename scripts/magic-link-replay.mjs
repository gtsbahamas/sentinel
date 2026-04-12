// Replay the magic-link severity cap on a saved scan result JSON using
// a hypothetical magicLinkRoutes config. Dedup runs first (as it would in
// a real scan) so the measurement reflects the final pipeline.
//
// Usage:
//   npx tsx scripts/magic-link-replay.mjs <result.json> <glob1> [glob2 ...]

import { readFileSync } from "fs";
import { dedupAIFindings } from "../src/layers/ai/dedup.ts";
import { applyMagicLinkSeverityCap, isMagicLinkPath } from "../src/layers/ai/magic-link.ts";

const [, , resultPath, ...globs] = process.argv;
if (!resultPath || globs.length === 0) {
  console.error("Usage: npx tsx scripts/magic-link-replay.mjs <result.json> <glob1> [glob2 ...]");
  process.exit(1);
}

const raw = JSON.parse(readFileSync(resultPath, "utf8"));

// Reconstruct a minimal endpoint list from the saved AI findings. Each
// finding's first-evidence file becomes an endpoint file. We need a `path`
// too — derive it from the project path prefix.
const projectPath = raw.meta?.project?.path ?? raw.runInfo?.projectPath;
function fileToPath(file) {
  // src/app/api/foo/bar/route.ts → /api/foo/bar
  const m = file.match(/src\/app(\/api\/[^/]+(?:\/[^/]+)*)\/route\.(?:ts|tsx|js|jsx)$/);
  return m ? m[1] : file;
}
const seen = new Set();
const endpoints = [];
for (const f of raw.findings.filter((x) => x.layer === "ai")) {
  const file = f.evidence[0]?.file;
  if (!file || seen.has(file)) continue;
  seen.add(file);
  endpoints.push({ path: fileToPath(file), file });
}

console.log(`Result: ${raw.findings.length} total, ${endpoints.length} unique AI endpoint files`);
console.log(`Config: magicLinkRoutes = ${JSON.stringify(globs)}\n`);

const matched = endpoints.filter((e) => isMagicLinkPath(e.path, globs));
console.log(`Endpoints matching magic-link globs: ${matched.length}`);
for (const e of matched) console.log(`  ${e.path}`);

const deduped = dedupAIFindings(raw.findings);
const capped = applyMagicLinkSeverityCap(deduped.findings, globs, endpoints);

function dist(findings) {
  const d = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) if (f.layer === "ai") d[f.severity]++;
  return d;
}
console.log(`\nAfter dedup:`, dist(deduped.findings));
console.log(`After cap:  `, dist(capped.findings));
console.log(`\nCapped: ${capped.cappedCount} findings`);

// Show the findings that got capped
if (capped.cappedCount > 0) {
  const beforeMap = new Map(deduped.findings.map((f) => [f.id, f]));
  console.log("\nCapped findings (before → after):");
  for (const f of capped.findings) {
    const before = beforeMap.get(f.id);
    if (before && before.severity !== f.severity) {
      console.log(`  ${before.severity} → ${f.severity}  [${f.domain}] ${f.title.slice(0, 80)}`);
    }
  }
}
