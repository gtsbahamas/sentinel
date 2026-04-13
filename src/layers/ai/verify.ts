import type {
  Finding,
  VerifyError,
  VerifyUsage,
  Verdict,
} from "../../model/types.js";
import type { ProjectContext } from "../context/types.js";
import type { AIProvider, GenerateRequest } from "./providers/base.js";
import { BudgetTracker } from "./budget.js";
import { VerdictSchema } from "./verify-schema.js";
import {
  VERIFY_SYSTEM_PREAMBLE,
  buildVerifyUserPrompt,
  REPORT_VERDICTS_TOOL,
} from "./verify-prompts.js";

interface VerifyFileArgs {
  file: string;
  source: string;
  findings: Finding[];
  context: ProjectContext | null;
  provider: AIProvider;
  budget: BudgetTracker;
}

interface VerifyFileResult {
  verdicts: Verdict[];
  usage: VerifyUsage;
  error: VerifyError | null;
}

function confirmAll(findings: Finding[], reason: string): Verdict[] {
  return findings.map((f) => ({
    findingId: f.id,
    decision: "confirm" as const,
    reason,
  }));
}

const ZERO_USAGE: VerifyUsage = {
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  estimatedCostUsd: 0,
};

export async function verifyFindingsForFile(args: VerifyFileArgs): Promise<VerifyFileResult> {
  const { file, source, findings, context, provider, budget } = args;
  if (findings.length === 0) {
    return { verdicts: [], usage: { ...ZERO_USAGE }, error: null };
  }

  const userPrompt = buildVerifyUserPrompt({ file, source, findings, context });
  const request: GenerateRequest = {
    systemPrompt: VERIFY_SYSTEM_PREAMBLE,
    projectSummary: "",
    userPrompt,
    toolDefinition: REPORT_VERDICTS_TOOL,
    maxInputTokens: 16000,
    maxOutputTokens: 4000,
  };

  let response;
  try {
    response = await provider.generateFindings(request);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      verdicts: confirmAll(findings, `verification failed: ${message}`),
      usage: { ...ZERO_USAGE },
      error: { kind: "provider", message, file },
    };
  }

  budget.recordUsage(response.usage);
  const usage: VerifyUsage = { ...response.usage };

  if (response.stopReason === "error") {
    const message = response.rawError ?? "provider error";
    return {
      verdicts: confirmAll(findings, `verification failed: ${message}`),
      usage,
      error: { kind: "provider", message, file },
    };
  }

  // The flat tool schema wraps verdicts in an object: { verdicts: [...] }.
  // Accept either the wrapper shape or a bare array of verdicts.
  let rawVerdicts: unknown[] = [];
  if (
    response.rawFindings.length === 1 &&
    typeof response.rawFindings[0] === "object" &&
    response.rawFindings[0] !== null &&
    "verdicts" in (response.rawFindings[0] as object)
  ) {
    const wrapper = response.rawFindings[0] as { verdicts?: unknown };
    rawVerdicts = Array.isArray(wrapper.verdicts) ? wrapper.verdicts : [];
  } else {
    rawVerdicts = response.rawFindings;
  }

  const parsed: Verdict[] = [];
  for (const raw of rawVerdicts) {
    // Strip null newSeverity that the flat schema permits; the Zod
    // discriminated union doesn't allow `null` on confirm/dismiss.
    let cleaned: unknown = raw;
    if (
      raw &&
      typeof raw === "object" &&
      "newSeverity" in (raw as object) &&
      (raw as { newSeverity: unknown }).newSeverity === null
    ) {
      const { newSeverity: _drop, ...rest } = raw as Record<string, unknown>;
      cleaned = rest;
    }
    const result = VerdictSchema.safeParse(cleaned);
    if (!result.success) {
      return {
        verdicts: confirmAll(findings, `verification failed: parse error`),
        usage,
        error: { kind: "parse", message: result.error.message.slice(0, 300), file },
      };
    }
    parsed.push(result.data as Verdict);
  }

  // Match verdicts back to candidates by findingId. Missing → default confirm.
  const byId = new Map<string, Verdict>();
  for (const v of parsed) {
    if (!byId.has(v.findingId)) byId.set(v.findingId, v);
  }
  const finalVerdicts: Verdict[] = findings.map((f) => {
    const v = byId.get(f.id);
    if (v) return v;
    return { findingId: f.id, decision: "confirm", reason: "no verdict returned" };
  });

  return { verdicts: finalVerdicts, usage, error: null };
}
