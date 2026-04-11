import type { AIConfig, AIRunResult, ProjectModel } from "../../model/types.js";
import type { AIProvider } from "./providers/base.js";
import { MockProvider } from "./providers/mock.js";
import { AnthropicProvider, ANTHROPIC_PRICING } from "./providers/anthropic.js";
import { OpenAIProvider, OPENAI_PRICING } from "./providers/openai.js";
import { BudgetTracker, type ProviderPricing } from "./budget.js";
import { runOrchestrator } from "./orchestrator.js";
import { runStageA } from "./stage-a.js";
import { runDryRun, type DryRunResult } from "./dry-run.js";
import { createRequire } from "module";

const require = createRequire(import.meta.url);

export { runDryRun };
export type { DryRunResult };

export async function runAI(
  model: ProjectModel,
  config: AIConfig,
  injectedProvider?: AIProvider,
): Promise<AIRunResult> {
  const provider = injectedProvider ?? createProvider(config);
  const pricing = pricingFor(config);
  const budget = new BudgetTracker(config.maxCostUsd, pricing);

  let priorityOrder: string[] | undefined;
  let stageA = null;
  if (config.deep) {
    stageA = await runStageA(model, provider, budget);
    priorityOrder = stageA?.priorityOrder;
  }

  const result = await runOrchestrator(model, config, provider, budget, priorityOrder);
  result.stageA = stageA;
  return result;
}

function createProvider(config: AIConfig): AIProvider {
  if (config.provider === "mock") return new MockProvider({});
  if (config.provider === "anthropic") {
    if (!config.dryRun && !process.env.ANTHROPIC_API_KEY) {
      throw new Error("ANTHROPIC_API_KEY is not set. Run `creds set anthropic-api-key` or export the env var.");
    }
    const Anthropic = require("@anthropic-ai/sdk").default;
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    return new AnthropicProvider(config.model, client);
  }
  if (config.provider === "openai") {
    if (!config.dryRun && !process.env.OPENAI_API_KEY) {
      throw new Error("OPENAI_API_KEY is not set. Run `creds set openai-api-key` or export the env var.");
    }
    const OpenAI = require("openai").default;
    const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    return new OpenAIProvider(config.model, client);
  }
  throw new Error(`Unknown AI provider: ${config.provider}`);
}

function pricingFor(config: AIConfig): ProviderPricing {
  if (config.provider === "anthropic") {
    return ANTHROPIC_PRICING[config.model] ?? ANTHROPIC_PRICING["claude-sonnet-4-6"];
  }
  if (config.provider === "openai") {
    return OPENAI_PRICING[config.model] ?? OPENAI_PRICING["gpt-5"];
  }
  return { inputPerMTokUsd: 0, outputPerMTokUsd: 0, cacheReadPerMTokUsd: 0, cacheWritePerMTokUsd: 0 };
}
