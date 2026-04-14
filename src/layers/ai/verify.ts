import { readFile } from "fs/promises";
import { resolve } from "path";
import type {
  Finding,
  ProjectModel,
  VerifyConfig,
  VerifyError,
  VerifyResult,
  VerifyUsage,
  Verdict,
  DismissedFinding,
  DowngradedFinding,
} from "../../model/types.js";
import type { ProjectContext } from "../context/types.js";
import type { AIProvider, GenerateRequest } from "./providers/base.js";
import { BudgetTracker, type ProviderPricing } from "./budget.js";
import { ANTHROPIC_PRICING } from "./providers/anthropic.js";
import { OPENAI_PRICING } from "./providers/openai.js";
import { isAtOrAbove } from "../../model/severity.js";
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
  // Different providers may surface this differently in rawFindings — handle
  // both: rawFindings is either the array directly OR a single-element array
  // containing the wrapper object.
  let rawVerdicts: unknown[] = [];
  if (response.rawFindings.length === 1 && typeof response.rawFindings[0] === "object" && response.rawFindings[0] !== null && "verdicts" in (response.rawFindings[0] as object)) {
    const wrapper = response.rawFindings[0] as { verdicts?: unknown };
    rawVerdicts = Array.isArray(wrapper.verdicts) ? wrapper.verdicts : [];
  } else {
    rawVerdicts = response.rawFindings;
  }

  const parsed: Verdict[] = [];
  for (const raw of rawVerdicts) {
    // Strip null newSeverity that the flat schema permits; Zod discriminator
    // doesn't allow it on confirm/dismiss.
    let cleaned: unknown = raw;
    if (raw && typeof raw === "object" && "newSeverity" in (raw as object) && (raw as { newSeverity: unknown }).newSeverity === null) {
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

function pricingForVerify(config: VerifyConfig): ProviderPricing {
  if (config.provider === "anthropic") {
    return ANTHROPIC_PRICING[config.model] ?? ANTHROPIC_PRICING["claude-haiku-4-5"];
  }
  if (config.provider === "openai") {
    return OPENAI_PRICING[config.model] ?? OPENAI_PRICING["gpt-5-mini"];
  }
  return { inputPerMTokUsd: 0, outputPerMTokUsd: 0, cacheReadPerMTokUsd: 0, cacheWritePerMTokUsd: 0 };
}

function addUsage(a: VerifyUsage, b: VerifyUsage): VerifyUsage {
  return {
    inputTokens: a.inputTokens + b.inputTokens,
    outputTokens: a.outputTokens + b.outputTokens,
    cacheReadTokens: a.cacheReadTokens + b.cacheReadTokens,
    cacheWriteTokens: a.cacheWriteTokens + b.cacheWriteTokens,
    estimatedCostUsd: a.estimatedCostUsd + b.estimatedCostUsd,
  };
}

export async function runVerify(
  model: ProjectModel,
  ruleFindings: Finding[],
  context: ProjectContext | null,
  config: VerifyConfig,
  provider: AIProvider,
): Promise<VerifyResult> {
  const start = Date.now();
  const pricing = pricingForVerify(config);
  const budget = new BudgetTracker(config.maxCostUsd, pricing);

  const confirmed: Finding[] = [];
  const dismissed: DismissedFinding[] = [];
  const downgraded: DowngradedFinding[] = [];
  const errors: VerifyError[] = [];
  let usage: VerifyUsage = { ...ZERO_USAGE };
  let budgetExhausted = false;
  let filesProcessed = 0;
  let findingsProcessed = 0;

  // Partition: sub-threshold passthrough, no-evidence passthrough, and
  // findings to verify (grouped by file).
  const toVerifyByFile = new Map<string, Finding[]>();
  for (const f of ruleFindings) {
    if (!isAtOrAbove(f.severity, config.minSeverity)) {
      confirmed.push(f);
      continue;
    }
    const file = f.evidence[0]?.file;
    if (!file) {
      confirmed.push(f);
      continue;
    }
    const list = toVerifyByFile.get(file) ?? [];
    list.push(f);
    toVerifyByFile.set(file, list);
  }

  const filesQueue: Array<[string, Finding[]]> = Array.from(toVerifyByFile.entries());

  // Process each verified verdict against the original Finding list.
  function applyVerdicts(fileFindings: Finding[], verdicts: Verdict[]): void {
    const verdictById = new Map<string, Verdict>();
    for (const v of verdicts) verdictById.set(v.findingId, v);
    for (const f of fileFindings) {
      const v = verdictById.get(f.id);
      if (!v || v.decision === "confirm") {
        confirmed.push(f);
      } else if (v.decision === "dismiss") {
        dismissed.push({ finding: f, reason: v.reason });
      } else if (v.decision === "downgrade") {
        const newF: Finding = { ...f, severity: v.newSeverity ?? f.severity };
        downgraded.push({ original: f, finding: newF, reason: v.reason });
      }
    }
  }

  // Synthesize confirms when budget is exhausted or read fails.
  function synthConfirm(fileFindings: Finding[], reason: string): void {
    for (const f of fileFindings) confirmed.push(f);
    void reason;
  }

  // Simple promise-pool with concurrency cap.
  const concurrency = Math.max(1, config.concurrency);
  let cursor = 0;
  async function worker(): Promise<void> {
    while (true) {
      const idx = cursor++;
      if (idx >= filesQueue.length) return;
      const [file, fileFindings] = filesQueue[idx];

      if (budget.exhausted()) {
        budgetExhausted = true;
        synthConfirm(fileFindings, "budget exhausted");
        continue;
      }

      let source: string;
      try {
        source = await readFile(resolve(model.meta.path, file), "utf8");
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        errors.push({ kind: "provider", message: `file read failed: ${message}`, file });
        synthConfirm(fileFindings, `file read failed: ${message}`);
        continue;
      }

      filesProcessed++;
      findingsProcessed += fileFindings.length;

      const result = await verifyFindingsForFile({
        file,
        source,
        findings: fileFindings,
        context,
        provider,
        budget,
      });
      usage = addUsage(usage, result.usage);
      if (result.error) errors.push(result.error);
      applyVerdicts(fileFindings, result.verdicts);

      if (budget.exhausted()) budgetExhausted = true;
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);

  return {
    confirmed,
    dismissed,
    downgraded,
    usage,
    errors,
    budgetExhausted,
    filesProcessed,
    findingsProcessed,
    durationMs: Date.now() - start,
  };
}
