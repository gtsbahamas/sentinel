import { randomUUID } from "crypto";
import type {
  Finding,
  ProbeConfig,
  ProbeRunResult,
  ProjectModel,
} from "../../model/types.js";
import { ProbeHttpClient, type ProbeLogEntry } from "./http-client.js";
import { ProbeCleanupRegistry } from "./cleanup-registry.js";
import { ProbeLogger } from "./probe-log.js";
import { resolveTargets } from "./target-resolver.js";
import { mergeProbeResults } from "./merge.js";
import { getProbeChecks } from "./checks/base.js";

export interface ProbeOrchestratorOptions {
  model: ProjectModel;
  findings: Finding[];
  config: ProbeConfig;
  sentinelVersion: string;
}

export async function runProbeOrchestrator(
  opts: ProbeOrchestratorOptions,
): Promise<{ result: ProbeRunResult; mergedFindings: Finding[] }> {
  const { model, findings, config, sentinelVersion } = opts;
  const runId = randomUUID().slice(0, 12);
  const start = Date.now();

  const logger = new ProbeLogger(config.logDir, runId);
  await logger.init();
  await logger.rotate(10);

  const onRequest = (entry: ProbeLogEntry) => {
    logger.append(entry).catch(() => {});
  };

  const client = new ProbeHttpClient({
    level: config.level,
    requestCaps: config.requestCaps,
    requestsPerSecond: config.requestsPerSecond,
    defaultTimeoutMs: config.timeoutMs,
    sentinelVersion,
    onRequest,
  });

  const registry = new ProbeCleanupRegistry();
  const targets = resolveTargets(model, findings, config.targetUrl!);
  const checks = getProbeChecks(config.level);

  const allResults: Array<import("./checks/base.js").ProbeCheckResult> = [];
  const allErrors: import("../../model/types.js").ProbeError[] = [];

  for (const target of targets) {
    const applicableChecks = checks.filter((c) => c.appliesTo(target, model));

    for (const check of applicableChecks) {
      try {
        const result = await check.run({
          target,
          model,
          client,
          registry,
          priorFindings: findings,
          runId,
        });
        allResults.push(result);
      } catch (err) {
        allErrors.push({
          kind: "check-error",
          message: err instanceof Error ? err.message : String(err),
          checkId: check.id,
          targetUrl: target.url,
        });
      }
    }
  }

  const cleanupResult = await registry.executeAll();

  const { findings: mergedFindings, newProbeFindings, confirmedIds, refutedIds } =
    mergeProbeResults(findings, allResults);

  const collectedErrors = [
    ...allErrors,
    ...allResults.flatMap((r) => r.errors),
  ];

  if (cleanupResult.failed > 0) {
    for (const f of cleanupResult.failures) {
      collectedErrors.push({
        kind: "cleanup-failed" as const,
        message: `${f.description}: ${f.error}`,
      });
    }
  }

  const result: ProbeRunResult = {
    findings: newProbeFindings,
    confirmedFindingIds: confirmedIds,
    refutedFindingIds: refutedIds,
    usedRequests: client.requestsUsed(),
    requestCap: client.requestCap(),
    aggressionLevel: config.level,
    targetOrigin: config.targetUrl!,
    errors: collectedErrors,
    cleanupObligationsExecuted: cleanupResult.executed,
    cleanupObligationsFailed: cleanupResult.failed,
    cleanupFailures: cleanupResult.failures.map((f) => ({
      obligation: f.description,
      error: f.error,
    })),
    probeLogPath: logger.getLogPath(),
    durationMs: Date.now() - start,
  };

  return { result, mergedFindings };
}
