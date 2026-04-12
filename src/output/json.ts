import type { AIRunResult, Finding, ProjectModel, Severity } from "../model/types.js";

export interface LayerTiming {
  recon_ms: number;
  rules_ms: number;
  ai_ms?: number;
  ai?: AIRunResult;
}

export function formatJson(
  model: ProjectModel,
  findings: Finding[],
  timing: LayerTiming,
): string {
  const summary: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0,
  };
  for (const f of findings) summary[f.severity]++;

  const aiLayerStatus = timing.ai ? "complete" : "skipped";

  const output = {
    version: "0.1.0",
    timestamp: new Date().toISOString(),
    project: {
      name: model.meta.name,
      path: model.meta.path,
      stack: model.meta.stack,
      framework: model.meta.framework,
    },
    layers: {
      recon: { status: "complete", duration_ms: timing.recon_ms },
      rules: { status: "complete", duration_ms: timing.rules_ms },
      ai: { status: aiLayerStatus, duration_ms: timing.ai_ms ?? 0 },
      probe: { status: "skipped", duration_ms: 0 },
    },
    runInfo: {
      recon_ms: timing.recon_ms,
      rules_ms: timing.rules_ms,
      ai_ms: timing.ai_ms ?? 0,
      ai: timing.ai
        ? {
            enabled: true,
            endpointsAnalyzed: timing.ai.endpointsAnalyzed,
            endpointsSkipped: timing.ai.endpointsSkipped,
            findingsCollapsed: timing.ai.findingsCollapsed,
            budgetExhausted: timing.ai.budgetExhausted,
            usage: timing.ai.usage,
            errors: timing.ai.errors,
            stageA: timing.ai.stageA,
          }
        : { enabled: false },
    },
    summary: {
      ...summary,
      total: findings.length,
      by_domain: Object.fromEntries(
        [...new Set(findings.map((f) => f.domain))].map((d) => [
          d,
          findings.filter((f) => f.domain === d).length,
        ]),
      ),
    },
    findings,
    model,
  };

  return JSON.stringify(output, null, 2);
}
