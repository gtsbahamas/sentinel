import type { Finding } from "../../model/types.js";

export interface Fixer {
  ruleId: string;
  type: "deterministic" | "ai";
  apply?: (fileContent: string, finding: Finding) => string | null;
  aiPromptId?: string;
}

export interface FixAttempt {
  findingId: string;
  ruleId: string;
  file: string;
  strategy: "deterministic" | "ai" | "manual";
  status: "fixed" | "skipped" | "failed";
  reason?: string;
  description?: string;
}

export interface FixResult {
  attempts: FixAttempt[];
  filesModified: string[];
}
