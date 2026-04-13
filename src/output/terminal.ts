import chalk from "chalk";
import type {
  Finding,
  ProjectModel,
  Severity,
  SecurityDomain,
  VerifyResult,
} from "../model/types.js";
import { compareSeverity } from "../model/severity.js";

const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

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

export function formatTerminal(
  model: ProjectModel,
  findings: Finding[],
  verifyResult?: VerifyResult | null,
  options?: { keepDismissed?: boolean },
): string {
  const lines: string[] = [];

  lines.push(chalk.bold("  SENTINEL v0.1.0 — Security Assessment"));
  lines.push(`  Target: ${model.meta.path}`);
  lines.push(`  Stack:  ${model.meta.stack} (${model.meta.framework})`);
  lines.push(`  Layers: Recon ${chalk.green("✓")}  Rules ${chalk.green("✓")}`);
  lines.push("");
  lines.push("  " + "─".repeat(50));
  lines.push("");

  const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
  const bySeverity = new Map<Severity, Finding[]>();
  for (const f of sorted) {
    if (!bySeverity.has(f.severity)) bySeverity.set(f.severity, []);
    bySeverity.get(f.severity)!.push(f);
  }

  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  for (const sev of order) {
    const list = bySeverity.get(sev) ?? [];
    if (list.length === 0) continue;
    lines.push(SEVERITY_COLOR[sev](`  ${sev.toUpperCase()} (${list.length})`));
    lines.push("");
    for (const f of list) {
      lines.push(`  ${chalk.bold(f.id)}  ${f.title}  ${chalk.dim("[" + f.domain + "]")}`);
      for (const ev of f.evidence) {
        lines.push(`           ${chalk.dim(ev.file + (ev.line ? `:${ev.line}` : ""))}`);
      }
      lines.push(`           ${chalk.dim("Layer: " + f.layer)}`);
      lines.push(`           ${chalk.dim("Fix: " + f.remediation)}`);
      if (f.references.length > 0) {
        lines.push(`           ${chalk.dim("Ref: " + f.references.join(", "))}`);
      }
      lines.push("");
    }
  }

  lines.push("  " + "─".repeat(50));
  lines.push("");
  lines.push(chalk.bold("  SUMMARY"));
  lines.push("");

  const header = "  ┌──────────────────────┬──────┬──────┬────────┬─────┬──────┐";
  const sep = "  ├──────────────────────┼──────┼──────┼────────┼─────┼──────┤";
  const footer = "  └──────────────────────┴──────┴──────┴────────┴─────┴──────┘";
  lines.push(header);
  lines.push("  │ Domain               │ Crit │ High │ Medium │ Low │ Info │");
  lines.push(sep);

  for (const domain of DOMAINS) {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) if (f.domain === domain) counts[f.severity]++;
    const total = counts.critical + counts.high + counts.medium + counts.low + counts.info;
    if (total === 0) continue;
    const label = domain.padEnd(20);
    lines.push(
      `  │ ${label} │ ${String(counts.critical).padStart(4)} │ ${String(counts.high).padStart(4)} │ ${String(counts.medium).padStart(6)} │ ${String(counts.low).padStart(3)} │ ${String(counts.info).padStart(4)} │`,
    );
  }
  lines.push(footer);
  lines.push("");

  const totals = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc as any)[f.severity] + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );
  lines.push(
    `  Total: ${totals.critical} critical, ${totals.high} high, ${totals.medium} medium, ${totals.low} low, ${totals.info} info`,
  );

  if (verifyResult) {
    lines.push("");
    lines.push("  " + "─".repeat(50));
    lines.push("");
    lines.push(chalk.bold("  VERIFICATION"));
    lines.push("");
    const confirmedCount = verifyResult.confirmed.length;
    const dismissedCount = verifyResult.dismissed.length;
    const downgradedCount = verifyResult.downgraded.length;
    lines.push(
      `  Verified: ${confirmedCount} confirmed, ${dismissedCount} dismissed, ${downgradedCount} downgraded`,
    );
    const cost = verifyResult.usage.estimatedCostUsd;
    lines.push(
      chalk.dim(`  (verifier: $${cost.toFixed(4)}, ${verifyResult.durationMs}ms)`),
    );

    if (verifyResult.errors.length > 0) {
      lines.push("");
      lines.push(
        chalk.yellow(
          `  ⚠ Verification errors: ${verifyResult.errors.length} (see JSON output for details)`,
        ),
      );
    }

    if (options?.keepDismissed && verifyResult.dismissed.length > 0) {
      lines.push("");
      lines.push(chalk.bold("  DISMISSED (SUSPECTED FALSE POSITIVE)"));
      lines.push("");
      for (const d of verifyResult.dismissed) {
        const f = d.finding;
        lines.push(
          `  ${chalk.bold(f.id)}  ${f.title}  ${chalk.dim("[" + f.domain + "]")}`,
        );
        for (const ev of f.evidence) {
          lines.push(
            `           ${chalk.dim(ev.file + (ev.line ? `:${ev.line}` : ""))}`,
          );
        }
        lines.push(`           ${chalk.dim("Dismissed: " + d.reason)}`);
        lines.push("");
      }
    }
  }

  return lines.join("\n");
}
