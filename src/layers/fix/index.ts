import { readFile, writeFile } from "fs/promises";
import type { Finding, AIConfig } from "../../model/types.js";
import type { FixAttempt, FixResult } from "./types.js";
import { getFixer } from "./registry.js";
import { runAIFixes } from "./ai/index.js";

export interface FixOptions {
  findings: Finding[];
  ruleFilter?: string[];
  noAI: boolean;
  dryRun: boolean;
  aiConfig?: AIConfig;
}

type FixStrategy = "deterministic" | "ai" | "manual";

function classifyFinding(finding: Finding): FixStrategy {
  if (!finding.ruleId) return "manual";
  const fixer = getFixer(finding.ruleId);
  if (!fixer) return "manual";
  return fixer.type;
}

export async function runFix(options: FixOptions): Promise<FixResult> {
  const attempts: FixAttempt[] = [];
  const filesModified: string[] = [];

  // 1. Filter findings by rule if --rule specified
  const findings =
    options.ruleFilter && options.ruleFilter.length > 0
      ? options.findings.filter((f) => f.ruleId && options.ruleFilter!.includes(f.ruleId))
      : options.findings;

  // 2. Classify each finding
  const deterministicFindings: Finding[] = [];
  const aiFindings: Finding[] = [];
  const manualFindings: Finding[] = [];

  for (const finding of findings) {
    const strategy = classifyFinding(finding);
    if (strategy === "deterministic") deterministicFindings.push(finding);
    else if (strategy === "ai") aiFindings.push(finding);
    else manualFindings.push(finding);
  }

  // Mark manual findings as skipped immediately
  for (const finding of manualFindings) {
    attempts.push({
      findingId: finding.id,
      ruleId: finding.ruleId ?? "unknown",
      file: finding.evidence[0]?.file ?? "unknown",
      strategy: "manual",
      status: "skipped",
      reason: "No automated fixer available for this rule",
    });
  }

  // 3. Phase 1: Apply deterministic fixes, grouped by file
  const deterministicByFile = new Map<string, Finding[]>();
  for (const finding of deterministicFindings) {
    const file = finding.evidence[0]?.file;
    if (!file) {
      attempts.push({
        findingId: finding.id,
        ruleId: finding.ruleId ?? "unknown",
        file: "unknown",
        strategy: "deterministic",
        status: "failed",
        reason: "Finding has no evidence file",
      });
      continue;
    }
    const group = deterministicByFile.get(file) ?? [];
    group.push(finding);
    deterministicByFile.set(file, group);
  }

  for (const [filePath, fileFindings] of deterministicByFile) {
    let fileContent: string;
    try {
      fileContent = await readFile(filePath, "utf-8");
    } catch (err) {
      for (const finding of fileFindings) {
        attempts.push({
          findingId: finding.id,
          ruleId: finding.ruleId ?? "unknown",
          file: filePath,
          strategy: "deterministic",
          status: "failed",
          reason: `Could not read file: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
      continue;
    }

    let currentContent = fileContent;
    let fileWasModified = false;

    for (const finding of fileFindings) {
      const fixer = getFixer(finding.ruleId!);
      if (!fixer || !fixer.apply) {
        attempts.push({
          findingId: finding.id,
          ruleId: finding.ruleId ?? "unknown",
          file: filePath,
          strategy: "deterministic",
          status: "skipped",
          reason: "Fixer has no apply function",
        });
        continue;
      }

      try {
        const patched = fixer.apply(currentContent, finding);
        if (patched === null) {
          attempts.push({
            findingId: finding.id,
            ruleId: finding.ruleId!,
            file: filePath,
            strategy: "deterministic",
            status: "skipped",
            reason: "Fixer returned null (pattern not found or already fixed)",
          });
        } else {
          currentContent = patched;
          fileWasModified = true;
          attempts.push({
            findingId: finding.id,
            ruleId: finding.ruleId!,
            file: filePath,
            strategy: "deterministic",
            status: "fixed",
            description: `Applied deterministic fix for ${finding.ruleId}`,
          });
        }
      } catch (err) {
        attempts.push({
          findingId: finding.id,
          ruleId: finding.ruleId!,
          file: filePath,
          strategy: "deterministic",
          status: "failed",
          reason: `Fixer threw an error: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }

    if (fileWasModified && !options.dryRun) {
      try {
        await writeFile(filePath, currentContent, "utf-8");
        filesModified.push(filePath);
      } catch (err) {
        // If write fails, retroactively update fixed attempts to failed
        for (const attempt of attempts) {
          if (attempt.file === filePath && attempt.status === "fixed") {
            attempt.status = "failed";
            attempt.reason = `Could not write file: ${err instanceof Error ? err.message : String(err)}`;
          }
        }
      }
    }
  }

  // 4. Phase 2: AI fixes (if enabled)
  if (!options.noAI && aiFindings.length > 0) {
    const aiConfig = options.aiConfig ?? {
      enabled: true,
      provider: "anthropic" as const,
      model: "claude-sonnet-4-6",
      deep: false,
      maxCostUsd: 5,
      maxTokensPerEndpoint: 4096,
      concurrency: 3,
      dryRun: options.dryRun,
      magicLinkRoutes: [],
    };

    // Group AI findings by file
    const aiByFile = new Map<string, Finding[]>();
    for (const finding of aiFindings) {
      const file = finding.evidence[0]?.file;
      if (!file) {
        attempts.push({
          findingId: finding.id,
          ruleId: finding.ruleId ?? "unknown",
          file: "unknown",
          strategy: "ai",
          status: "failed",
          reason: "Finding has no evidence file",
        });
        continue;
      }
      const group = aiByFile.get(file) ?? [];
      group.push(finding);
      aiByFile.set(file, group);
    }

    const aiResult = await runAIFixes(aiByFile, {
      aiConfig,
      dryRun: options.dryRun,
    });

    attempts.push(...aiResult.attempts);
    filesModified.push(...aiResult.filesModified);
  } else if (options.noAI && aiFindings.length > 0) {
    for (const finding of aiFindings) {
      attempts.push({
        findingId: finding.id,
        ruleId: finding.ruleId ?? "unknown",
        file: finding.evidence[0]?.file ?? "unknown",
        strategy: "ai",
        status: "skipped",
        reason: "--no-ai flag set",
      });
    }
  }

  return {
    attempts,
    filesModified: [...new Set(filesModified)],
  };
}
