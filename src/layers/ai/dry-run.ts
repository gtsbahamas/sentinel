import type { AIConfig, ProjectModel } from "../../model/types.js";
import type { AIProvider } from "./providers/base.js";
import { buildContext } from "./context-builder.js";
import { buildProjectSummary, buildEndpointPrompt, SYSTEM_PREAMBLE, REPORT_FINDINGS_TOOL } from "./prompts.js";

export interface DryRunResult {
  endpointCount: number;
  totalInputTokens: number;
  avgPerEndpointTokens: number;
  projectSummaryTokens: number;
  estimatedCostUsd: number;
  maxCostUsd: number;
  withinBudget: boolean;
}

export async function runDryRun(
  model: ProjectModel,
  config: AIConfig,
  provider: AIProvider,
): Promise<DryRunResult> {
  const summary = buildProjectSummary(model);
  const summaryEst = provider.estimateTokens({
    systemPrompt: SYSTEM_PREAMBLE,
    projectSummary: summary,
    userPrompt: "",
    toolDefinition: REPORT_FINDINGS_TOOL,
    maxInputTokens: config.maxTokensPerEndpoint,
    maxOutputTokens: 2000,
  });

  let totalInput = 0;
  let totalCost = 0;

  for (const endpoint of model.endpoints) {
    const ctx = await buildContext(endpoint, model, config.maxTokensPerEndpoint);
    if (!ctx) continue;
    const prompt = buildEndpointPrompt(endpoint, ctx.handlerSource, ctx.adjacent);
    const est = provider.estimateTokens({
      systemPrompt: SYSTEM_PREAMBLE,
      projectSummary: summary,
      userPrompt: prompt,
      toolDefinition: REPORT_FINDINGS_TOOL,
      maxInputTokens: config.maxTokensPerEndpoint,
      maxOutputTokens: 2000,
    });
    totalInput += est.inputTokens;
    totalCost += est.estimatedCostUsd;
  }

  return {
    endpointCount: model.endpoints.length,
    totalInputTokens: totalInput,
    avgPerEndpointTokens: model.endpoints.length > 0 ? Math.round(totalInput / model.endpoints.length) : 0,
    projectSummaryTokens: summaryEst.inputTokens,
    estimatedCostUsd: totalCost,
    maxCostUsd: config.maxCostUsd,
    withinBudget: totalCost <= config.maxCostUsd,
  };
}
