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
import { runAI, runDryRun, createProvider, type DryRunResult } from "../layers/ai/index.js";
import { MockProvider } from "../layers/ai/providers/mock.js";
import { formatTerminal } from "../output/terminal.js";
import { formatJson } from "../output/json.js";
import { formatHtml } from "../output/html.js";
import { isAtOrAbove } from "../model/severity.js";
import type { AIConfig, AIRunResult, Severity } from "../model/types.js";
import type { SentinelConfig } from "../config.js";

export interface ScanOptions {
  path: string;
  format: "terminal" | "json" | "html";
  failOn?: Severity;
  outFile?: string;
  ai?: boolean;
  aiDeep?: boolean;
  aiDryRun?: boolean;
  aiProvider?: "anthropic" | "openai" | "mock";
  aiModel?: string;
  aiMaxCost?: number;
  aiConcurrency?: number;
}

const PROVIDER_DEFAULT_MODELS: Record<string, string> = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-5",
  mock: "mock",
};

function mergeAIConfig(config: SentinelConfig, options: ScanOptions): AIConfig {
  const provider = options.aiProvider ?? config.ai.provider;
  // When the user switches provider via CLI without also passing --ai-model,
  // the config.ai.model default (Anthropic-flavored) would be sent to the
  // wrong provider. Fall through to the provider's native default instead.
  const providerChanged = options.aiProvider && options.aiProvider !== config.ai.provider;
  const model =
    options.aiModel ??
    (providerChanged ? PROVIDER_DEFAULT_MODELS[provider] ?? config.ai.model : config.ai.model);

  return {
    enabled: options.ai ?? config.ai.enabled,
    provider,
    model,
    deep: options.aiDeep ?? config.ai.deep,
    maxCostUsd: options.aiMaxCost ?? config.ai.maxCostUsd,
    maxTokensPerEndpoint: config.ai.maxTokensPerEndpoint,
    concurrency: options.aiConcurrency ?? config.ai.concurrency,
    dryRun: options.aiDryRun ?? false,
  };
}

export async function runScan(options: ScanOptions): Promise<number> {
  const config = await loadConfig(options.path);

  const reconStart = Date.now();
  const model = await runRecon(options.path, config.exclude);
  const recon_ms = Date.now() - reconStart;

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
  const ruleFindings = await runRules(model);
  const rules_ms = Date.now() - rulesStart;

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
    try {
      aiResult = await runAI(model, aiConfig);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`AI layer failed: ${msg}\n`);
      process.stderr.write("Continuing with rule findings only.\n");
      // aiResult stays null, scan proceeds with rule findings
    }
    ai_ms = Date.now() - aiStart;
    // NOTE: do NOT mutate model.findings — aiResult.findings stays separate.
  }

  const allFindings = [...ruleFindings, ...(aiResult?.findings ?? [])];

  if (options.format === "json") {
    const body = formatJson(model, allFindings, { recon_ms, rules_ms, ai_ms, ai: aiResult ?? undefined });
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
    process.stdout.write(formatTerminal(model, allFindings));
    if (aiResult) {
      process.stdout.write("\n" + formatAIReport(aiResult, aiConfig) + "\n");
    }
    process.stdout.write("\n");
  }

  const failOn = options.failOn ?? config.severity.failOn;
  const hasBlockingFinding = allFindings.some((f) => isAtOrAbove(f.severity, failOn));
  return hasBlockingFinding ? 1 : 0;
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
  return `AI Analysis
───────────
Endpoints analyzed: ${result.endpointsAnalyzed} / ${result.endpointsAnalyzed + result.endpointsSkipped}
Findings:           ${result.findings.length}${counts ? ` (${counts})` : ""}${collapsedNote}
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
