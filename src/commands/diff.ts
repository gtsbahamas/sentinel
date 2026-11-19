import { readFile } from "fs/promises";
import chalk from "chalk";
import type { Finding, IgnoredFinding, Severity } from "../model/types.js";
import { isAtOrAbove } from "../model/severity.js";
import { VERSION } from "../version.js";

export interface DiffOptions {
  baseline: string;
  current: string;
  format: "terminal" | "json";
  failOn?: Severity;
}

export interface DiffResult {
  added: Finding[];
  removed: Finding[];
  // In the baseline, and in the current report only as ignored (a
  // `sentinel:ignore` comment was added, or the config's `ignore` now covers
  // it). Not resolved, so not in `removed`.
  nowIgnored: Finding[];
  unchanged: Finding[];
  baselineTotal: number;
  currentTotal: number;
}

// Stable dedupe key. The Finding.id field already contains rule + file + line,
// but it can drift when unrelated lines move. We build a narrower key based on
// only ruleId, file, and line to keep noise down.
function key(f: Finding): string {
  const file = f.evidence[0]?.file ?? "";
  const line = f.evidence[0]?.line ?? 0;
  return `${f.ruleId ?? "UNKNOWN"}|${file}|${line}`;
}

export interface Report {
  findings: Finding[];
  // Under a path the config's `ignore` lists.
  ignored: Finding[];
  // Covered by a `sentinel:ignore` comment.
  ignoredByComment: IgnoredFinding[];
}

async function loadReport(path: string): Promise<Report> {
  const raw = await readFile(path, "utf-8");
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed.findings)) {
    throw new Error(`${path} is not a sentinel JSON report (missing findings array)`);
  }
  // Reports written before ignored findings were listed have neither list.
  return {
    findings: parsed.findings,
    ignored: Array.isArray(parsed.ignored) ? parsed.ignored : [],
    ignoredByComment: Array.isArray(parsed.ignored_by_comment) ? parsed.ignored_by_comment : [],
  };
}

/** Diff two reports, telling a finding that was fixed from one that was only ignored. */
export function diffReports(baseline: Report, current: Report): DiffResult {
  const result = diffFindings(baseline.findings, current.findings);
  const ignoredKeys = new Set([
    ...current.ignored.map(key),
    ...current.ignoredByComment.map((i) => key(i.finding)),
  ]);
  return {
    ...result,
    removed: result.removed.filter((f) => !ignoredKeys.has(key(f))),
    nowIgnored: result.removed.filter((f) => ignoredKeys.has(key(f))),
  };
}

export function diffFindings(baseline: Finding[], current: Finding[]): DiffResult {
  const baselineMap = new Map<string, Finding>();
  for (const f of baseline) baselineMap.set(key(f), f);

  const currentMap = new Map<string, Finding>();
  for (const f of current) currentMap.set(key(f), f);

  const added: Finding[] = [];
  const removed: Finding[] = [];
  const unchanged: Finding[] = [];

  for (const [k, f] of currentMap.entries()) {
    if (baselineMap.has(k)) unchanged.push(f);
    else added.push(f);
  }
  for (const [k, f] of baselineMap.entries()) {
    if (!currentMap.has(k)) removed.push(f);
  }

  return {
    added,
    removed,
    nowIgnored: [],
    unchanged,
    baselineTotal: baseline.length,
    currentTotal: current.length,
  };
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

function formatDelta(added: number, removed: number): string {
  const a = added > 0 ? chalk.red(`+${added}`) : chalk.dim(`+${added}`);
  const r = removed > 0 ? chalk.green(`-${removed}`) : chalk.dim(`-${removed}`);
  return `${a} / ${r}`;
}

function formatTerminalDiff(result: DiffResult): string {
  const lines: string[] = [];
  const addedBy = countBySeverity(result.added);
  const removedBy = countBySeverity(result.removed);

  lines.push(chalk.bold("  SENTINEL DIFF"));
  lines.push(`  Baseline: ${result.baselineTotal} findings`);
  lines.push(`  Current:  ${result.currentTotal} findings`);
  lines.push("");
  lines.push("  " + "─".repeat(50));
  lines.push("");
  lines.push(chalk.bold("  Changes by severity  (added / removed)"));
  lines.push("");
  for (const sev of SEVERITY_ORDER) {
    const a = addedBy[sev];
    const r = removedBy[sev];
    if (a === 0 && r === 0) continue;
    lines.push(`    ${sev.padEnd(10)} ${formatDelta(a, r)}`);
  }
  lines.push("");

  if (result.added.length > 0) {
    lines.push("  " + "─".repeat(50));
    lines.push("");
    // Build per-layer breakdown
    const newByLayer = result.added.reduce<Record<string, number>>((a, f) => {
      a[f.layer] = (a[f.layer] ?? 0) + 1;
      return a;
    }, {});
    const newLayerLabel = Object.entries(newByLayer)
      .map(([layer, n]) => `${layer}: ${n}`)
      .join(", ");
    const newHeader = `  NEW FINDINGS (${result.added.length}${result.added.length > 0 ? ` [${newLayerLabel}]` : ""})`;
    lines.push(chalk.red.bold(newHeader));
    lines.push("");
    for (const f of result.added) {
      const sev = f.severity.toUpperCase().padEnd(8);
      const where = f.evidence[0]?.file
        ? `${f.evidence[0].file}${f.evidence[0].line ? `:${f.evidence[0].line}` : ""}`
        : "";
      lines.push(`    ${chalk.red(sev)} ${chalk.bold(f.ruleId ?? "?")}  ${f.title}`);
      if (where) lines.push(`             ${chalk.dim(where)}`);
    }
    lines.push("");
  }

  if (result.removed.length > 0) {
    lines.push("  " + "─".repeat(50));
    lines.push("");
    lines.push(chalk.green.bold(`  RESOLVED (${result.removed.length})`));
    lines.push("");
    for (const f of result.removed) {
      const sev = f.severity.toUpperCase().padEnd(8);
      const where = f.evidence[0]?.file
        ? `${f.evidence[0].file}${f.evidence[0].line ? `:${f.evidence[0].line}` : ""}`
        : "";
      lines.push(`    ${chalk.green(sev)} ${chalk.bold(f.ruleId ?? "?")}  ${f.title}`);
      if (where) lines.push(`             ${chalk.dim(where)}`);
    }
    lines.push("");
  }

  if (result.nowIgnored.length > 0) {
    lines.push("  " + "─".repeat(50));
    lines.push("");
    lines.push(chalk.yellow.bold(`  NOW IGNORED, NOT RESOLVED (${result.nowIgnored.length})`));
    lines.push("");
    for (const f of result.nowIgnored) {
      const sev = f.severity.toUpperCase().padEnd(8);
      const where = f.evidence[0]?.file ?? "";
      lines.push(`    ${chalk.yellow(sev)} ${chalk.bold(f.ruleId ?? "?")}  ${f.title}`);
      if (where) lines.push(`             ${chalk.dim(where + " (ignored)")}`);
    }
    lines.push("");
  }

  if (result.added.length === 0 && result.removed.length === 0 && result.nowIgnored.length === 0) {
    lines.push(chalk.green("  No changes — baseline matches current scan."));
    lines.push("");
  }

  return lines.join("\n");
}

export function formatJsonDiff(result: DiffResult): string {
  return JSON.stringify(
    {
      version: VERSION,
      generated_at: new Date().toISOString(),
      baseline_total: result.baselineTotal,
      current_total: result.currentTotal,
      added: result.added,
      removed: result.removed,
      now_ignored: result.nowIgnored,
      unchanged_count: result.unchanged.length,
      summary: {
        added_by_severity: countBySeverity(result.added),
        removed_by_severity: countBySeverity(result.removed),
      },
    },
    null,
    2,
  );
}

export async function runDiff(options: DiffOptions): Promise<number> {
  const [baseline, current] = await Promise.all([
    loadReport(options.baseline),
    loadReport(options.current),
  ]);
  const result = diffReports(baseline, current);

  if (options.format === "json") {
    process.stdout.write(formatJsonDiff(result));
    process.stdout.write("\n");
  } else {
    process.stdout.write(formatTerminalDiff(result));
    process.stdout.write("\n");
  }

  // Exit non-zero if any *new* finding is at or above the fail-on threshold.
  // Resolved findings never fail the diff — progress is good.
  const failOn = options.failOn;
  if (failOn) {
    const newBlocking = result.added.some((f) => isAtOrAbove(f.severity, failOn));
    return newBlocking ? 1 : 0;
  }
  return result.added.length > 0 ? 1 : 0;
}
