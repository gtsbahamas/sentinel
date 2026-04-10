import type { Severity } from "./types.js";

const RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function severityRank(severity: Severity): number {
  return RANK[severity];
}

export function isAtOrAbove(severity: Severity, threshold: Severity): boolean {
  return RANK[severity] >= RANK[threshold];
}

export function compareSeverity(a: Severity, b: Severity): number {
  return RANK[b] - RANK[a];
}
