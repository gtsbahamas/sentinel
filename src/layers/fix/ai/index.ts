import { readFile, writeFile } from "fs/promises";
import { createRequire } from "module";
import type { Finding, AIConfig } from "../../../model/types.js";
import type { FixAttempt } from "../types.js";
import { getFixer } from "../registry.js";
import { getPromptTemplate } from "./prompts.js";
import { validateAIResponse } from "./validator.js";

const require = createRequire(import.meta.url);

/**
 * Strip markdown code fences and preamble text from AI responses.
 * Some models return "Looking at the code..." followed by ```ts\n...\n```
 * instead of raw file content as instructed.
 */
function stripMarkdownFences(text: string): string {
  // Try to extract content from a markdown code block
  const fenceMatch = text.match(/```(?:typescript|ts|javascript|js)?\s*\n([\s\S]*?)```\s*$/);
  if (fenceMatch) {
    return fenceMatch[1].trimEnd();
  }
  // No fences found — check if there's preamble text before actual code
  // (AI sometimes writes explanation then raw code without fences)
  const lines = text.split("\n");
  const firstImportIdx = lines.findIndex((l) => /^import\s/.test(l.trim()));
  if (firstImportIdx > 0) {
    // Check if the first non-blank line is prose (doesn't start with a code token)
    const firstNonBlank = lines.slice(0, firstImportIdx).find((l) => l.trim().length > 0);
    if (firstNonBlank) {
      const trimmed = firstNonBlank.trim();
      const codeStarters = /^(import\s|export\s|const\s|let\s|var\s|function\s|class\s|type\s|interface\s|\/\/|\/\*|'use |"use )/;
      if (!codeStarters.test(trimmed)) {
        // First non-blank line is prose — strip everything before the first real import
        return lines.slice(firstImportIdx).join("\n").trimEnd();
      }
    }
  }
  return text;
}

export interface AIFixOptions {
  aiConfig: AIConfig;
  dryRun?: boolean;
  concurrency?: number;
}

interface ChatResult {
  text: string;
  error?: string;
}

/**
 * Calls the AI provider with a simple system + user prompt and returns the raw text response.
 * This is a lightweight wrapper separate from the findings-generation provider interface,
 * because fix prompts need plain text responses (not tool-use JSON).
 */
async function callAIForFix(
  system: string,
  userPrompt: string,
  config: AIConfig,
): Promise<ChatResult> {
  if (config.provider === "mock") {
    // Mock provider: echo back the original file content unchanged (for tests)
    const marker = "File content:\n```\n";
    const start = userPrompt.indexOf(marker);
    if (start !== -1) {
      const contentStart = start + marker.length;
      const end = userPrompt.indexOf("\n```\n", contentStart);
      const text = end !== -1 ? userPrompt.slice(contentStart, end) : userPrompt.slice(contentStart);
      return { text };
    }
    return { text: userPrompt };
  }

  if (config.provider === "anthropic") {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      return { text: "", error: "ANTHROPIC_API_KEY is not set" };
    }
    try {
      const Anthropic = require("@anthropic-ai/sdk").default;
      const client = new Anthropic({ apiKey, timeout: 90_000 });
      const response = await client.messages.create({
        model: config.model,
        max_tokens: 16384,
        system,
        messages: [{ role: "user", content: userPrompt }],
      });
      if (response.stop_reason === "max_tokens") {
        return { text: "", error: "AI output truncated (stop_reason=max_tokens). Raise max_tokens or split the fix." };
      }
      const textBlock = response.content.find((b: { type: string }) => b.type === "text");
      const text = (textBlock as { type: "text"; text: string } | undefined)?.text ?? "";
      return { text };
    } catch (err) {
      return { text: "", error: err instanceof Error ? err.message : String(err) };
    }
  }

  if (config.provider === "openai") {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return { text: "", error: "OPENAI_API_KEY is not set" };
    }
    try {
      const OpenAI = require("openai").default;
      const client = new OpenAI({ apiKey, timeout: 90_000 });
      const response = await client.chat.completions.create({
        model: config.model,
        messages: [
          { role: "system", content: system },
          { role: "user", content: userPrompt },
        ],
        max_completion_tokens: 16384,
      });
      if (response.choices[0]?.finish_reason === "length") {
        return { text: "", error: "AI output truncated (finish_reason=length). Raise max_completion_tokens or split the fix." };
      }
      const text = response.choices[0]?.message?.content ?? "";
      return { text };
    } catch (err) {
      return { text: "", error: err instanceof Error ? err.message : String(err) };
    }
  }

  return { text: "", error: `Unknown AI provider: ${config.provider}` };
}

/**
 * Process a single file: read it, apply AI prompt groups sequentially,
 * write back if changed. Returns attempts and modified file path (if any).
 */
async function fixSingleFile(
  filePath: string,
  findings: Finding[],
  options: AIFixOptions,
): Promise<{ attempts: FixAttempt[]; modified?: string }> {
  const attempts: FixAttempt[] = [];

  // Group findings by their fixer's aiPromptId
  const promptGroups = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (!finding.ruleId) continue;
    const fixer = getFixer(finding.ruleId);
    if (!fixer || fixer.type !== "ai" || !fixer.aiPromptId) continue;
    const group = promptGroups.get(fixer.aiPromptId) ?? [];
    group.push(finding);
    promptGroups.set(fixer.aiPromptId, group);
  }

  if (promptGroups.size === 0) return { attempts };

  // Read the current file content once
  let fileContent: string;
  try {
    fileContent = await readFile(filePath, "utf-8");
  } catch (err) {
    for (const finding of findings) {
      if (!finding.ruleId) continue;
      const fixer = getFixer(finding.ruleId);
      if (fixer?.type !== "ai") continue;
      attempts.push({
        findingId: finding.id,
        ruleId: finding.ruleId,
        file: filePath,
        strategy: "ai",
        status: "failed",
        reason: `Could not read file: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
    return { attempts };
  }

  // Apply each prompt group in sequence (each may build on the previous fix)
  let currentContent = fileContent;

  for (const [promptId, groupFindings] of promptGroups) {
    const template = getPromptTemplate(promptId);
    if (!template) {
      for (const finding of groupFindings) {
        attempts.push({
          findingId: finding.id,
          ruleId: finding.ruleId ?? promptId,
          file: filePath,
          strategy: "ai",
          status: "skipped",
          reason: `No prompt template found for promptId: ${promptId}`,
        });
      }
      continue;
    }

    if (options.dryRun) {
      for (const finding of groupFindings) {
        attempts.push({
          findingId: finding.id,
          ruleId: finding.ruleId ?? promptId,
          file: filePath,
          strategy: "ai",
          status: "skipped",
          reason: "dry-run mode",
        });
      }
      continue;
    }

    const userPrompt = template.buildUserPrompt(currentContent, groupFindings);
    const result = await callAIForFix(template.system, userPrompt, options.aiConfig);

    // Strip markdown fences / preamble that models sometimes add despite instructions
    if (result.text) {
      result.text = stripMarkdownFences(result.text);
      // Fix common Zod API mistake: .error.errors → .error.issues
      result.text = result.text.replace(/\.error\.errors\b/g, ".error.issues");
    }

    if (result.error || !result.text) {
      for (const finding of groupFindings) {
        attempts.push({
          findingId: finding.id,
          ruleId: finding.ruleId ?? promptId,
          file: filePath,
          strategy: "ai",
          status: "failed",
          reason: result.error ?? "AI returned empty response",
        });
      }
      continue;
    }

    const validation = validateAIResponse(currentContent, result.text);
    if (!validation.valid) {
      for (const finding of groupFindings) {
        attempts.push({
          findingId: finding.id,
          ruleId: finding.ruleId ?? promptId,
          file: filePath,
          strategy: "ai",
          status: "failed",
          reason: `Validation failed: ${validation.reason}`,
        });
      }
      continue;
    }

    // Patch accepted — update current content and mark as fixed
    currentContent = result.text;
    for (const finding of groupFindings) {
      attempts.push({
        findingId: finding.id,
        ruleId: finding.ruleId ?? promptId,
        file: filePath,
        strategy: "ai",
        status: "fixed",
        description: `Applied AI fix via prompt template ${promptId}`,
      });
    }
  }

  // Write the final content if it changed
  if (currentContent !== fileContent && !options.dryRun) {
    await writeFile(filePath, currentContent, "utf-8");
    return { attempts, modified: filePath };
  }

  return { attempts };
}

export async function runAIFixes(
  findingsByFile: Map<string, Finding[]>,
  options: AIFixOptions,
): Promise<{ attempts: FixAttempt[]; filesModified: string[] }> {
  const concurrency = options.concurrency ?? 3;
  const entries = Array.from(findingsByFile.entries());

  // Process files with bounded concurrency
  const allAttempts: FixAttempt[] = [];
  const filesModified: string[] = [];
  let idx = 0;

  async function next(): Promise<void> {
    while (idx < entries.length) {
      const i = idx++;
      const [filePath, findings] = entries[i];
      const result = await fixSingleFile(filePath, findings, options);
      allAttempts.push(...result.attempts);
      if (result.modified) filesModified.push(result.modified);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, entries.length) }, () => next());
  await Promise.all(workers);

  return { attempts: allAttempts, filesModified };
}
