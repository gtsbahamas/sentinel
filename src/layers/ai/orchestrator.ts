import type { AIConfig, AIError, AIRunResult, ApiEndpoint, Finding, ProjectModel } from "../../model/types.js";
import type { AIProvider, GenerateRequest } from "./providers/base.js";
import type { BudgetTracker } from "./budget.js";
import { buildContext } from "./context-builder.js";
import { buildProjectSummary, buildEndpointPrompt, SYSTEM_PREAMBLE, REPORT_FINDINGS_TOOL } from "./prompts.js";
import { AIFindingSchema, aiToFinding } from "./schema.js";

export async function runOrchestrator(
  model: ProjectModel,
  config: AIConfig,
  provider: AIProvider,
  budget: BudgetTracker,
  priorityOrder?: string[],
): Promise<AIRunResult> {
  const start = Date.now();
  const projectSummary = buildProjectSummary(model);
  const findings: Finding[] = [];
  const errors: AIError[] = [];
  let analyzed = 0;
  let skipped = 0;
  let budgetExhausted = false;

  const ordered = orderEndpoints(model.endpoints, priorityOrder);

  const concurrency = Math.max(1, config.concurrency);
  const queue = [...ordered];
  let halted = false;

  async function worker(): Promise<void> {
    while (!halted) {
      const endpoint = queue.shift();
      if (!endpoint) return;

      if (budget.exhausted()) {
        // Only the first worker to detect exhaustion claims the remaining queue.
        // Others just count themselves to avoid double-counting under concurrency > 1.
        if (!halted) {
          halted = true;
          budgetExhausted = true;
          skipped += queue.length + 1;
        } else {
          skipped += 1;
        }
        return;
      }

      const ctx = await buildContext(endpoint, model, config.maxTokensPerEndpoint);
      if (!ctx) {
        skipped++;
        errors.push({ kind: "context", message: "handler exceeds per-endpoint token cap or unreadable", endpoint: endpoint.path });
        continue;
      }

      const userPrompt = buildEndpointPrompt(endpoint, ctx.handlerSource, ctx.adjacent);
      const request: GenerateRequest = {
        systemPrompt: SYSTEM_PREAMBLE,
        projectSummary,
        userPrompt,
        toolDefinition: REPORT_FINDINGS_TOOL,
        maxInputTokens: config.maxTokensPerEndpoint,
        maxOutputTokens: 2000,
      };

      const estimate = provider.estimateTokens(request);
      if (budget.wouldExceed(estimate)) {
        if (!halted) {
          halted = true;
          budgetExhausted = true;
          skipped += queue.length + 1;
        } else {
          skipped += 1;
        }
        return;
      }

      try {
        const response = await provider.generateFindings(request);
        budget.recordUsage(response.usage);

        if (response.stopReason === "error") {
          skipped++;
          errors.push({ kind: "provider", message: response.rawError ?? "provider error", endpoint: endpoint.path });
          continue;
        }

        analyzed++;
        for (const raw of response.rawFindings) {
          const parsed = AIFindingSchema.safeParse(raw);
          if (!parsed.success) {
            errors.push({ kind: "parse", message: parsed.error.message.slice(0, 300), endpoint: endpoint.path });
            continue;
          }
          findings.push(aiToFinding(parsed.data));
        }
      } catch (err) {
        skipped++;
        errors.push({
          kind: "provider",
          message: err instanceof Error ? err.message : String(err),
          endpoint: endpoint.path,
        });
      }
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);

  return {
    findings,
    usage: budget.summary(),
    stageA: null,
    errors,
    budgetExhausted,
    endpointsAnalyzed: analyzed,
    endpointsSkipped: skipped,
    durationMs: Date.now() - start,
  };
}

function orderEndpoints(endpoints: ApiEndpoint[], priorityOrder?: string[]): ApiEndpoint[] {
  if (!priorityOrder || priorityOrder.length === 0) return [...endpoints];
  // Key on method+path so REST endpoints with the same path but different
  // methods (GET /api/users vs POST /api/users) remain distinct.
  const endpointKey = (e: ApiEndpoint) => `${e.method} ${e.path}`;
  const ordered: ApiEndpoint[] = [];
  const seen = new Set<string>();
  // Priority list is path-based (Stage A emits paths only). For each path in
  // the priority list, pull every endpoint with that path (may be multiple
  // methods). Preserve the method order as they appear in endpoints[].
  for (const p of priorityOrder) {
    for (const e of endpoints) {
      if (e.path === p && !seen.has(endpointKey(e))) {
        ordered.push(e);
        seen.add(endpointKey(e));
      }
    }
  }
  for (const e of endpoints) {
    if (!seen.has(endpointKey(e))) ordered.push(e);
  }
  return ordered;
}
