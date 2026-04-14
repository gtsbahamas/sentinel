import { readFile } from "fs/promises";
import { existsSync } from "fs";
import { resolve } from "path";
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
import { registerFixer, resetFixerRegistry } from "../layers/fix/registry.js";
import { crypto001Fixer } from "../layers/fix/deterministic/crypto-001.js";
import { crypto002Fixer } from "../layers/fix/deterministic/crypto-002.js";
import { log005Fixer } from "../layers/fix/deterministic/log-005.js";
import { infra006Fixer } from "../layers/fix/deterministic/infra-006.js";
import { getPromptTemplate } from "../layers/fix/ai/prompts.js";
import { runFix } from "../layers/fix/index.js";
import type { Finding, AIConfig } from "../model/types.js";
import type { FixAttempt } from "../layers/fix/types.js";

export interface FixCommandOptions {
  path: string;
  from?: string;
  rule?: string[];
  dryRun?: boolean;
  noAI?: boolean;
  aiProvider?: "anthropic" | "openai" | "mock";
  aiModel?: string;
  aiMaxCost?: number;
  aiConcurrency?: number;
}

const AI_RULE_IDS = ["INPUT-005", "AUTH-002", "API-004"];

function registerAllFixers(): void {
  resetFixerRegistry();

  // Deterministic fixers
  registerFixer(crypto001Fixer);
  registerFixer(crypto002Fixer);
  registerFixer(log005Fixer);
  registerFixer(infra006Fixer);

  // AI fixers — registered as type "ai" with aiPromptId pointing to prompt templates
  for (const ruleId of AI_RULE_IDS) {
    const template = getPromptTemplate(ruleId);
    if (template) {
      registerFixer({
        ruleId,
        type: "ai",
        aiPromptId: ruleId,
      });
    }
  }
}

async function acquireFindings(options: FixCommandOptions): Promise<Finding[]> {
  if (options.from) {
    // Load findings from a JSON report file
    const reportPath = resolve(options.from);
    if (!existsSync(reportPath)) {
      throw new Error(`Report file not found: ${reportPath}`);
    }
    const raw = await readFile(reportPath, "utf-8");
    const parsed = JSON.parse(raw) as { findings?: Finding[] };
    if (!Array.isArray(parsed.findings)) {
      throw new Error(`Report file does not contain a 'findings' array: ${reportPath}`);
    }
    return parsed.findings;
  }

  // Run a fresh scan to get findings
  const config = await loadConfig(options.path);

  const model = await runRecon(options.path, config.exclude);

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

  return await runRules(model);
}

function buildAIConfig(options: FixCommandOptions, baseProvider: "anthropic" | "openai" | "mock"): AIConfig {
  const provider = options.aiProvider ?? baseProvider;
  const PROVIDER_DEFAULT_MODELS: Record<string, string> = {
    anthropic: "claude-sonnet-4-6",
    openai: "gpt-5",
    mock: "mock",
  };
  return {
    enabled: true,
    provider,
    model: options.aiModel ?? PROVIDER_DEFAULT_MODELS[provider] ?? "claude-sonnet-4-6",
    deep: false,
    maxCostUsd: options.aiMaxCost ?? 2.0,
    maxTokensPerEndpoint: 8000,
    concurrency: options.aiConcurrency ?? 3,
    dryRun: options.dryRun ?? false,
    magicLinkRoutes: [],
  };
}

function formatFixResults(attempts: FixAttempt[], filesModified: string[], dryRun: boolean): string {
  const fixed = attempts.filter((a) => a.status === "fixed");
  const skipped = attempts.filter((a) => a.status === "skipped");
  const failed = attempts.filter((a) => a.status === "failed");

  const lines: string[] = [];
  lines.push("");
  lines.push("Fix Results");
  lines.push("───────────");

  if (dryRun) {
    lines.push("Mode: dry-run (no files written)");
    lines.push("");
  }

  if (fixed.length > 0) {
    lines.push(`✓ Fixed (${fixed.length}):`);
    for (const a of fixed) {
      lines.push(`  ${a.ruleId}  ${a.file}${a.description ? `  — ${a.description}` : ""}`);
    }
    lines.push("");
  }

  if (failed.length > 0) {
    lines.push(`✗ Failed (${failed.length}):`);
    for (const a of failed) {
      lines.push(`  ${a.ruleId}  ${a.file}${a.reason ? `  — ${a.reason}` : ""}`);
    }
    lines.push("");
  }

  if (skipped.length > 0) {
    lines.push(`⊘ Skipped (${skipped.length}):`);
    for (const a of skipped) {
      lines.push(`  ${a.ruleId}  ${a.file}${a.reason ? `  — ${a.reason}` : ""}`);
    }
    lines.push("");
  }

  lines.push(`Summary: ${fixed.length} fixed, ${failed.length} failed, ${skipped.length} skipped`);

  if (!dryRun && filesModified.length > 0) {
    lines.push("");
    lines.push(`Files modified (${filesModified.length}):`);
    for (const f of filesModified) {
      lines.push(`  ${f}`);
    }
  }

  lines.push("");
  return lines.join("\n");
}

export async function runFixCommand(options: FixCommandOptions): Promise<number> {
  const config = await loadConfig(options.path);

  registerAllFixers();

  let findings: Finding[];
  try {
    findings = await acquireFindings(options);
  } catch (err) {
    process.stderr.write(`Error acquiring findings: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }

  if (findings.length === 0) {
    process.stdout.write("No findings to fix.\n");
    return 0;
  }

  const aiConfig = buildAIConfig(options, config.ai.provider);

  const result = await runFix({
    findings,
    ruleFilter: options.rule && options.rule.length > 0 ? options.rule : undefined,
    noAI: options.noAI ?? false,
    dryRun: options.dryRun ?? false,
    aiConfig,
  });

  process.stdout.write(formatFixResults(result.attempts, result.filesModified, options.dryRun ?? false));

  return 0;
}
