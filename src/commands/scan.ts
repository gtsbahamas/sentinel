import { writeFile, mkdir } from "fs/promises";
import { dirname, join, resolve } from "path";
import { loadConfig } from "../config.js";
import { runRecon } from "../layers/recon/index.js";
import { runRules, registerRules, resetRegistry } from "../layers/rules/index.js";
import { secretsExposureRules } from "../layers/rules/domains/secrets-exposure.js";
import { inputInjectionRules } from "../layers/rules/domains/input-injection.js";
import { authAccessControlRules } from "../layers/rules/domains/auth-access-control.js";
import { fileUploadRules } from "../layers/rules/domains/file-upload.js";
import { supplyChainRules } from "../layers/rules/domains/supply-chain.js";
import { cryptographyRules } from "../layers/rules/domains/cryptography.js";
import { loggingMonitoringRules } from "../layers/rules/domains/logging-monitoring.js";
import { apiSecurityRules } from "../layers/rules/domains/api-security.js";
import { businessLogicRules } from "../layers/rules/domains/business-logic.js";
import { infrastructureRules } from "../layers/rules/domains/infrastructure.js";
import { runAI, runDryRun, createProvider, runVerify, type DryRunResult } from "../layers/ai/index.js";
import { MockProvider } from "../layers/ai/providers/mock.js";
import { formatTerminal } from "../output/terminal.js";
import { formatJson } from "../output/json.js";
import { formatHtml } from "../output/html.js";
import { pushToShipSafe, resolveShipSafeConfig } from "../output/shipsafe.js";
import { inferContext, readContext } from "../layers/context/index.js";
import { applyContextSuppressions } from "../layers/context/suppression.js";
import { isAtOrAbove } from "../model/severity.js";
import { mergeVerifyConfig, type VerifyOptions } from "./verify-options.js";
import type { AIConfig, AIRunResult, Finding, Severity, VerifyResult } from "../model/types.js";
import type { SentinelConfig } from "../config.js";
import { ScanEventEmitter } from "../dashboard/events.js";

export interface ScanOptions extends VerifyOptions {
  path: string;
  format: "terminal" | "json" | "html";
  failOn?: Severity;
  outFile?: string;
  ai?: boolean;
  aiDeep?: boolean;
  aiDryRun?: boolean;
  aiProvider?: "anthropic" | "openai" | "ollama" | "mock";
  aiModel?: string;
  aiMaxCost?: number;
  aiConcurrency?: number;
  // Repeatable CLI flag: --ai-magic-link <glob>. Merges with
  // ai.magicLinkRoutes from .sentinelrc.json.
  aiMagicLinkRoutes?: string[];
  dashboard?: boolean;
  dashboardPort?: number;
  emitter?: ScanEventEmitter;
  // ShipSafe push (opt-in). When url+token+projectId are present (via flags or
  // env), the scan posts findings to a ShipSafe instance after primary output
  // is written. Network failures never fail the scan.
  shipsafeUrl?: string;
  shipsafeToken?: string;
  shipsafeProjectId?: string;
  shipsafeRunId?: string;
}

const PROVIDER_DEFAULT_MODELS: Record<string, string> = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-5",
  ollama: "llama3.1:8b",
  mock: "mock",
};

const PROVIDER_DEEP_MODELS: Record<string, string> = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-5",
  ollama: "qwen3.6:27b",
  mock: "mock",
};

function mergeAIConfig(config: SentinelConfig, options: ScanOptions): AIConfig {
  const provider = options.aiProvider ?? config.ai.provider;
  // When the user switches provider via CLI without also passing --ai-model,
  // the config.ai.model default (Anthropic-flavored) would be sent to the
  // wrong provider. Fall through to the provider's native default instead.
  const providerChanged = options.aiProvider && options.aiProvider !== config.ai.provider;
  const isDeep = options.aiDeep ?? config.ai.deep;
  const defaultModels = isDeep ? PROVIDER_DEEP_MODELS : PROVIDER_DEFAULT_MODELS;
  const model =
    options.aiModel ??
    (providerChanged ? defaultModels[provider] ?? config.ai.model : config.ai.model);

  return {
    enabled: options.ai ?? config.ai.enabled,
    provider,
    model,
    deep: options.aiDeep ?? config.ai.deep,
    maxCostUsd: options.aiMaxCost ?? config.ai.maxCostUsd,
    maxTokensPerEndpoint: config.ai.maxTokensPerEndpoint,
    concurrency: options.aiConcurrency ?? config.ai.concurrency,
    baseUrl: config.ai.baseUrl,
    dryRun: options.aiDryRun ?? false,
    // CLI-supplied globs append to (not replace) the config. Deduplicate so
    // users passing overlapping patterns on the CLI + config don't pay twice.
    magicLinkRoutes: Array.from(
      new Set([...config.ai.magicLinkRoutes, ...(options.aiMagicLinkRoutes ?? [])]),
    ),
  };
}

export async function runScan(options: ScanOptions): Promise<number> {
  const config = await loadConfig(options.path);

  const emitter = options.emitter ?? (options.dashboard ? new ScanEventEmitter() : null);

  // Dynamic import for dashboard server (only loaded when needed)
  let dashboardHandle: import("../dashboard/server.js").DashboardHandle | null = null;
  if (options.dashboard && emitter) {
    const { startDashboard } = await import("../dashboard/server.js");
    dashboardHandle = await startDashboard(emitter, { port: options.dashboardPort, openBrowser: true });
    process.stderr.write(`Dashboard: http://localhost:${dashboardHandle.port}\n`);
  }

  emitter?.emitEvent({ type: "scan:start", project: options.path, timestamp: Date.now() });

  const reconStart = Date.now();
  emitter?.emitEvent({ type: "layer:start", layer: "recon", timestamp: Date.now() });
  const model = await runRecon(options.path, config.exclude, emitter ?? undefined);
  const recon_ms = Date.now() - reconStart;
  emitter?.emitEvent({ type: "layer:complete", layer: "recon", durationMs: recon_ms, timestamp: Date.now() });

  // Context phase: load saved context or auto-infer
  const contextFromFile = await readContext(options.path);
  const context = contextFromFile ?? await inferContext(model);
  if (!contextFromFile) {
    process.stderr.write("No .sentinel/context.json found. Using auto-inferred context.\n");
    process.stderr.write("Run `sentinel context` to reduce false positives.\n\n");
  }

  resetRegistry();
  registerRules(secretsExposureRules);
  registerRules(inputInjectionRules);
  registerRules(authAccessControlRules);
  registerRules(fileUploadRules);
  registerRules(supplyChainRules);
  registerRules(cryptographyRules);
  registerRules(loggingMonitoringRules);
  registerRules(apiSecurityRules);
  registerRules(businessLogicRules);
  registerRules(infrastructureRules);

  const rulesStart = Date.now();
  emitter?.emitEvent({ type: "layer:start", layer: "rules", timestamp: Date.now() });
  const ruleFindings = await runRules(model, context, emitter ?? undefined);
  const rules_ms = Date.now() - rulesStart;
  emitter?.emitEvent({ type: "layer:complete", layer: "rules", durationMs: rules_ms, timestamp: Date.now() });

  let aiResult: AIRunResult | null = null;
  let ai_ms = 0;
  const aiConfig = mergeAIConfig(config, options);

  // Dry-run path: emit estimate, return 0, make NO real provider calls.
  // Use the real provider so pricing is accurate — estimateTokens() is pure
  // math with no network. The mock path only applies when the user explicitly
  // picks --ai-provider mock.
  if (options.aiDryRun) {
    const dryConfig: AIConfig = { ...aiConfig, dryRun: true, enabled: true };
    const estimateProvider =
      dryConfig.provider === "mock" ? new MockProvider({}) : createProvider(dryConfig);
    const estimate = await runDryRun(model, dryConfig, estimateProvider);
    process.stdout.write(formatDryRunReport(estimate, dryConfig) + "\n");
    return 0;
  }

  if (aiConfig.enabled) {
    const aiStart = Date.now();
    emitter?.emitEvent({ type: "layer:start", layer: "ai", timestamp: Date.now() });
    try {
      aiResult = await runAI(model, aiConfig, undefined, context, emitter ?? undefined);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`AI layer failed: ${msg}\n`);
      process.stderr.write("Continuing with rule findings only.\n");
      // aiResult stays null, scan proceeds with rule findings
    }
    ai_ms = Date.now() - aiStart;
    emitter?.emitEvent({ type: "layer:complete", layer: "ai", durationMs: ai_ms, timestamp: Date.now() });
    // NOTE: do NOT mutate model.findings — aiResult.findings stays separate.
  }

  // Apply project-level context suppressions to rule findings BEFORE the
  // verification pass. Suppression is a cheap project-level filter (excluded
  // paths, delegations); there is no point paying for AI verification on
  // findings that a user-authored context file has already marked as noise.
  const suppressedRuleFindings = applyContextSuppressions(ruleFindings, context);

  // Verification pass — reclassifies surviving rule findings using the AI
  // layer. Findings that pass verification (confirmed + downgraded) re-enter
  // the main finding stream. Dismissed findings drop out unless keepDismissed
  // is set.
  let verifyResult: VerifyResult | null = null;
  // mergeVerifyConfig reads config.ai.provider (file-level), but we want the
  // CLI's --ai-provider override to flow through to the verifier as well.
  // Override after merge so `--verify --ai-provider mock` works as expected.
  const verifyConfig = { ...mergeVerifyConfig(options, config), provider: aiConfig.provider };
  let ruleFindingsForReport: Finding[] = suppressedRuleFindings;
  if (verifyConfig.enabled) {
    try {
      const verifyProvider = createProvider({
        ...aiConfig,
        provider: verifyConfig.provider,
        model: verifyConfig.model,
      });
      verifyResult = await runVerify(model, suppressedRuleFindings, context, verifyConfig, verifyProvider);
      ruleFindingsForReport = [
        ...verifyResult.confirmed,
        ...verifyResult.downgraded.map((d) => d.finding),
      ];
      if (verifyConfig.keepDismissed) {
        ruleFindingsForReport = [
          ...ruleFindingsForReport,
          ...verifyResult.dismissed.map((d) => d.finding),
        ];
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`Verification pass failed: ${msg}\n`);
      process.stderr.write("Continuing with unverified rule findings.\n");
      // verifyResult stays null; ruleFindingsForReport stays as suppressedRuleFindings.
    }
  }

  // AI-layer findings are suppressed separately (context applies project-wide,
  // but verify only examines rule findings — the AI layer has its own
  // context-awareness via buildProjectSummary).
  const allFindings = applyContextSuppressions(
    [...ruleFindingsForReport, ...(aiResult?.findings ?? [])],
    context,
  );

  // Emit suppressed findings to dashboard (after context filtering)
  if (emitter) {
    for (const f of allFindings) {
      emitter.emitEvent({
        type: "finding",
        data: {
          id: f.id,
          ruleId: f.ruleId,
          severity: f.severity,
          title: f.title,
          description: f.description,
          impact: f.impact,
          file: f.evidence[0]?.file ?? "",
          line: f.evidence[0]?.line,
          domain: f.domain,
          layer: f.layer,
          remediation: f.remediation,
        },
      });
    }
  }

  if (options.format === "json") {
    const body = formatJson(
      model,
      allFindings,
      { recon_ms, rules_ms, ai_ms, ai: aiResult ?? undefined },
      verifyResult,
    );
    if (options.outFile) {
      const dest = resolve(options.outFile);
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, body, "utf-8");
      process.stdout.write(`Wrote JSON report to ${dest}\n`);
    } else {
      process.stdout.write(body);
    }
  } else if (options.format === "html") {
    const body = formatHtml(model, allFindings, { recon_ms, rules_ms });
    const dest = resolve(options.outFile ?? join(options.path, config.output.dir, `scan-${Date.now()}.html`));
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, body, "utf-8");
    process.stdout.write(`Wrote HTML report to ${dest}\n`);
  } else {
    process.stdout.write(
      formatTerminal(model, allFindings, verifyResult, { keepDismissed: verifyConfig.keepDismissed }),
    );
    if (aiResult) {
      process.stdout.write("\n" + formatAIReport(aiResult, aiConfig) + "\n");
    }
    process.stdout.write("\n");
  }

  // ShipSafe push (opt-in, non-fatal). Runs AFTER terminal/json/html output
  // so a push failure can't corrupt the primary scan artifact. Wrapped in a
  // blanket try/catch as belt-and-suspenders: the adapter already swallows
  // errors internally, but we never want an unhandled rejection here to
  // crash the scan exit code.
  const shipsafeConfig = resolveShipSafeConfig({
    url: options.shipsafeUrl,
    token: options.shipsafeToken,
    projectId: options.shipsafeProjectId,
    sentinelRunId: options.shipsafeRunId,
  });
  if (shipsafeConfig) {
    try {
      await pushToShipSafe(allFindings, shipsafeConfig);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[shipsafe] unexpected push error: ${msg}\n`);
    }
  }

  const failOn = options.failOn ?? config.severity.failOn;
  const hasBlockingFinding = allFindings.some((f) => isAtOrAbove(f.severity, failOn));
  const exitCode = hasBlockingFinding ? 1 : 0;

  // Emit scan:complete summary
  const findingCounts = allFindings.reduce<Record<string, number>>((a, f) => {
    a[f.severity] = (a[f.severity] ?? 0) + 1;
    return a;
  }, {});
  emitter?.emitEvent({
    type: "scan:complete",
    summary: {
      routes: model.routes.length,
      endpoints: model.endpoints.length,
      dataModels: model.dataModels.length,
      externalServices: 0,
      findings: {
        critical: findingCounts["critical"] ?? 0,
        high: findingCounts["high"] ?? 0,
        medium: findingCounts["medium"] ?? 0,
        low: findingCounts["low"] ?? 0,
        info: findingCounts["info"] ?? 0,
      },
      durationMs: recon_ms + rules_ms + ai_ms,
    },
    timestamp: Date.now(),
  });

  // Keep process alive if dashboard is running
  if (dashboardHandle) {
    process.stderr.write(`\nDashboard running at http://localhost:${dashboardHandle.port}\nPress Ctrl+C to exit.\n`);
    await new Promise<void>((resolve) => {
      process.on("SIGINT", async () => {
        await dashboardHandle!.close();
        resolve();
      });
    });
  }

  return exitCode;
}

function formatAIReport(result: AIRunResult, config: AIConfig): string {
  const findingCounts = result.findings.reduce<Record<string, number>>((a, f) => {
    a[f.severity] = (a[f.severity] ?? 0) + 1;
    return a;
  }, {});
  const counts = ["critical", "high", "medium", "low"]
    .filter((s) => findingCounts[s])
    .map((s) => `${s}: ${findingCounts[s]}`)
    .join(", ");
  const totalInputConsumed = result.usage.inputTokens + result.usage.cacheReadTokens;
  const cacheRate =
    totalInputConsumed > 0
      ? `${Math.round((result.usage.cacheReadTokens / totalInputConsumed) * 100)}%`
      : "0%";
  const collapsedNote = result.findingsCollapsed > 0 ? ` (+${result.findingsCollapsed} collapsed)` : "";
  const cappedNote = result.magicLinkCapped > 0 ? ` (${result.magicLinkCapped} magic-link capped)` : "";
  return `AI Analysis
───────────
Endpoints analyzed: ${result.endpointsAnalyzed} / ${result.endpointsAnalyzed + result.endpointsSkipped}
Findings:           ${result.findings.length}${counts ? ` (${counts})` : ""}${collapsedNote}${cappedNote}
Errors:             ${result.errors.length}
Tokens:
  Input:       ${result.usage.inputTokens.toLocaleString()}
  Cached read: ${result.usage.cacheReadTokens.toLocaleString()} (cache hit rate: ${cacheRate})
  Output:      ${result.usage.outputTokens.toLocaleString()}
Cost estimate: $${result.usage.estimatedCostUsd.toFixed(2)} (cap $${config.maxCostUsd.toFixed(2)})
Duration: ${Math.round(result.durationMs / 1000)}s${result.budgetExhausted ? "\nWARNING: budget exhausted — scan halted early" : ""}`;
}

function formatDryRunReport(e: DryRunResult, config: AIConfig): string {
  return `AI Dry Run
──────────
Endpoints to analyze: ${e.endpointCount}
Project summary tokens: ${e.projectSummaryTokens.toLocaleString()} (cached after first call)
Per-endpoint avg tokens: ${e.avgPerEndpointTokens.toLocaleString()}
Total input tokens: ~${e.totalInputTokens.toLocaleString()}
Estimated cost: $${e.estimatedCostUsd.toFixed(2)} (${config.provider} ${config.model})
Budget cap: $${e.maxCostUsd.toFixed(2)}
Status: ${e.withinBudget ? "within budget" : "EXCEEDS BUDGET"}

Run without --ai-dry-run to execute.`;
}
