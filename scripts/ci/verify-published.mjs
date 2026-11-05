#!/usr/bin/env node
// Release read-back (gtsbahamas/fleet#8880): fail unless npm serves this
// checkout's version as `latest` and its tarball carries the modules the
// release is for. A merged-but-unpublished engine fails here, not in a
// verifier's sandbox weeks later.
//
// Usage: node scripts/ci/verify-published.mjs [--wait-seconds N]

import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REQUIRED_FILES = [
  "package/dist/cli.js",
  "package/dist/layers/rules/osv.js",
  "package/dist/layers/recon/lockfile.js",
  "package/dist/monitor/advisory-alerts.js",
];

// Rules the release must carry, by the text that only the shipped version has
// (gtsbahamas/fleet#8881: 0.3.1 was latest while LLM-006 sat unpublished).
const REQUIRED_CONTENT = [
  { file: "package/dist/layers/rules/domains/llm-features.js", needles: ['"LLM-006"', "approvalGuards"] },
];

const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8"));
const waitArg = process.argv.indexOf("--wait-seconds");
const waitSeconds = waitArg > 0 ? Number(process.argv[waitArg + 1]) : 0;
const registry = "https://registry.npmjs.org";

async function packument() {
  const res = await fetch(`${registry}/${encodeURIComponent(pkg.name)}`, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`registry returned HTTP ${res.status}`);
  return res.json();
}

const deadline = Date.now() + waitSeconds * 1000;
let doc;
for (;;) {
  doc = await packument();
  if (doc.versions?.[pkg.version] && doc["dist-tags"]?.latest === pkg.version) break;
  if (Date.now() >= deadline) {
    console.error(`FAIL: ${pkg.name}@${pkg.version} is not npm latest (latest=${doc["dist-tags"]?.latest}, published=${Boolean(doc.versions?.[pkg.version])})`);
    process.exit(1);
  }
  await new Promise((r) => setTimeout(r, 10_000));
}

const meta = doc.versions[pkg.version];
const tgz = await fetch(meta.dist.tarball);
if (!tgz.ok) throw new Error(`tarball returned HTTP ${tgz.status}`);
const dir = mkdtempSync(join(tmpdir(), "verify-published-"));
const file = join(dir, "pkg.tgz");
writeFileSync(file, Buffer.from(await tgz.arrayBuffer()));
const listing = new Set(execFileSync("tar", ["-tzf", file], { encoding: "utf8" }).split("\n"));
const missing = REQUIRED_FILES.filter((f) => !listing.has(f));
if (missing.length) {
  console.error(`FAIL: ${pkg.name}@${pkg.version} tarball lacks ${missing.join(", ")}`);
  process.exit(1);
}
for (const { file: inner, needles } of REQUIRED_CONTENT) {
  const text = execFileSync("tar", ["-xzOf", file, inner], { encoding: "utf8" });
  const absent = needles.filter((n) => !text.includes(n));
  if (absent.length) {
    console.error(`FAIL: ${pkg.name}@${pkg.version} ${inner} lacks ${absent.join(", ")}`);
    process.exit(1);
  }
}
console.log(
  `OK: ${pkg.name}@${pkg.version} is npm latest, published ${doc.time?.[pkg.version]}, gitHead ${meta.gitHead ?? "n/a"}, tarball has ${REQUIRED_FILES.length} required files and ${REQUIRED_CONTENT.length} required rule modules`,
);
