import type { AIUsage } from "../../../model/types.js";
import type { TokenEstimate } from "../budget.js";

export interface AIProvider {
  readonly name: "anthropic" | "openai" | "ollama" | "mock";
  generateFindings(request: GenerateRequest): Promise<GenerateResponse>;
  estimateTokens(request: GenerateRequest): TokenEstimate;
}

export interface GenerateRequest {
  systemPrompt: string;
  projectSummary: string;
  userPrompt: string;
  toolDefinition: ToolDefinition;
  maxInputTokens: number;
  maxOutputTokens: number;
}

export interface GenerateResponse {
  rawFindings: unknown[];
  usage: AIUsage;
  stopReason: "end_turn" | "tool_use" | "max_tokens" | "error";
  rawError?: string;
}

export interface ToolDefinition {
  name: "report_findings" | "report_project_risks" | "report_verdicts";
  description: string;
  schema: object;
}
