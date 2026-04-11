import type { ProjectModel, StageARiskSummary } from "../../model/types.js";
import type { AIProvider } from "./providers/base.js";
import type { BudgetTracker } from "./budget.js";
import { StageARiskSchema } from "./schema.js";
import { buildStageAPrompt, buildProjectSummary, SYSTEM_PREAMBLE } from "./prompts.js";

const STAGE_A_TOOL = {
  name: "report_findings" as const,
  description: "Report project-wide security risks and a priority order of endpoints to analyze next.",
  schema: {
    type: "object",
    properties: {
      projectRisks: {
        type: "array",
        items: {
          type: "object",
          properties: {
            domain: { type: "string" },
            description: { type: "string" },
            affectedEndpoints: { type: "array", items: { type: "string" } },
            severity: { type: "string" },
          },
          required: ["domain", "description", "affectedEndpoints", "severity"],
        },
      },
      priorityOrder: { type: "array", items: { type: "string" } },
    },
    required: ["projectRisks", "priorityOrder"],
    additionalProperties: false,
  },
};

export async function runStageA(
  model: ProjectModel,
  provider: AIProvider,
  budget: BudgetTracker,
): Promise<StageARiskSummary | null> {
  if (budget.exhausted()) return null;

  try {
    const response = await provider.generateFindings({
      systemPrompt: SYSTEM_PREAMBLE,
      projectSummary: buildProjectSummary(model),
      userPrompt: buildStageAPrompt(model),
      toolDefinition: STAGE_A_TOOL,
      maxInputTokens: 12000,
      maxOutputTokens: 2000,
    });

    budget.recordUsage(response.usage);

    if (response.stopReason === "error") return null;
    if (response.rawFindings.length === 0) return null;

    const parsed = StageARiskSchema.safeParse(response.rawFindings[0]);
    if (!parsed.success) return null;
    return parsed.data;
  } catch {
    return null;
  }
}
