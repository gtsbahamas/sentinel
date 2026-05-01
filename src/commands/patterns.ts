import { readFile, writeFile } from "fs/promises";
import { existsSync } from "fs";
import { join, resolve } from "path";
import chalk from "chalk";
import { loadConfig } from "../config.js";
import { runRecon } from "../layers/recon/index.js";
import type { InferredPattern, ProjectModel } from "../model/types.js";

export interface PatternsOptions {
  init?: boolean;
  force?: boolean;
}

// Convention block written into .sentinelrc.json by `--init`. Kept narrow on
// purpose so future fields (e.g., severity, exceptions) can be added without
// breaking older configs.
interface Convention {
  match: string;
  require: string;
}

const CONFIG_FILENAME = ".sentinelrc.json";

/**
 * Format the inferred patterns for terminal display. Designed for sales-demo
 * readability — see bite spec for the canonical example.
 */
export function formatPatterns(
  projectPath: string,
  patterns: InferredPattern[],
): string {
  const lines: string[] = [];
  lines.push(chalk.bold(`Sentinel patterns inferred from ${projectPath}`));
  lines.push("");

  if (patterns.length === 0) {
    lines.push(`No auth patterns inferred from ${projectPath}.`);
    lines.push("");
    lines.push(
      "Sentinel needs at least 5 endpoints in a path group with at least 60% convergence on",
    );
    lines.push(
      "a single auth helper. This usually means the project is small or hasn't",
    );
    lines.push("established a single canonical auth helper yet.");
    lines.push("");
    lines.push("You can still declare conventions explicitly in .sentinelrc.json:");
    lines.push("");
    lines.push("  {");
    lines.push('    "conventions": [');
    lines.push(
      '      { "match": "src/app/api/admin/**", "require": "requireStaffPermission" }',
    );
    lines.push("    ]");
    lines.push("  }");
    return lines.join("\n");
  }

  for (const p of patterns) {
    const pct = Math.round(p.prevalence * 100);
    const dominantCount = Math.round(p.prevalence * p.sampleSize);
    lines.push(`  ${chalk.cyan(p.pathGlob)}`);
    lines.push(`    ${chalk.green("✓")} ${chalk.bold(p.dominantHelper + "()")}`);
    lines.push(
      `    ${dominantCount} of ${p.sampleSize} endpoints (${pct}%)`,
    );
    if (p.evidenceFiles.length > 0) {
      lines.push(`    ${chalk.dim("e.g. " + p.evidenceFiles[0])}`);
      for (let i = 1; i < p.evidenceFiles.length; i++) {
        lines.push(`         ${chalk.dim(p.evidenceFiles[i])}`);
      }
    }
    lines.push("");
  }

  const word = patterns.length === 1 ? "pattern" : "patterns";
  lines.push(
    `${patterns.length} ${word} inferred. Run \`sentinel patterns --init\` to lock these in`,
  );
  lines.push(
    "as a .sentinelrc.json so PATTERN-001 deviations become CONVENTION-001",
  );
  lines.push("deviations (more precise, less noisy).");

  return lines.join("\n");
}

/**
 * Convert inferred patterns to declarative convention blocks. Pure function so
 * tests don't need filesystem.
 */
export function patternsToConventions(patterns: InferredPattern[]): Convention[] {
  return patterns.map((p) => ({
    match: p.pathGlob,
    require: p.dominantHelper,
  }));
}

/**
 * Read .sentinelrc.json if present, return {} otherwise. Returns the raw parsed
 * JSON (not the strict ConfigSchema-validated shape) because we want to round-
 * trip user-authored fields that the schema may not know about (this command
 * shouldn't silently strip them).
 */
async function readRawConfig(projectPath: string): Promise<Record<string, unknown>> {
  const configPath = join(projectPath, CONFIG_FILENAME);
  if (!existsSync(configPath)) return {};
  const raw = await readFile(configPath, "utf-8");
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return {};
  } catch {
    // Malformed JSON — surface it rather than silently overwrite.
    throw new Error(
      `Cannot parse ${CONFIG_FILENAME} as JSON. Fix the syntax error before running --init.`,
    );
  }
}

/**
 * Merge inferred patterns into a config object as a `conventions` array.
 *
 * If `existing.conventions` already exists and `force` is false, throws with a
 * helpful message. The intent is "your conventions are sacred — we won't
 * overwrite them by accident."
 */
export function mergeConventions(
  existingConfig: Record<string, unknown>,
  patterns: InferredPattern[],
  force: boolean,
): Record<string, unknown> {
  const conventions = patternsToConventions(patterns);
  const hasExisting =
    Array.isArray(existingConfig.conventions) &&
    (existingConfig.conventions as unknown[]).length > 0;

  if (hasExisting && !force) {
    throw new Error(
      `${CONFIG_FILENAME} already contains a 'conventions' array. Pass --force to overwrite.`,
    );
  }

  return {
    ...existingConfig,
    conventions,
  };
}

export async function runPatterns(
  rawPath: string,
  options: PatternsOptions,
): Promise<void> {
  const projectPath = resolve(rawPath);

  // Build a ProjectModel via recon. The same machinery scan.ts uses — see
  // src/commands/scan.ts:118. We deliberately skip the rules layer and AI
  // layer; pattern inference runs inside recon and that's all we need.
  const config = await loadConfig(projectPath);
  const model: ProjectModel = await runRecon(projectPath, config.exclude);
  const patterns = model.inferredPatterns ?? [];

  if (options.init) {
    if (patterns.length === 0) {
      process.stderr.write(
        `No patterns inferred from ${projectPath}. Nothing to write.\n`,
      );
      process.stderr.write(
        "Sentinel needs at least 5 endpoints in a path group with at least 60% convergence.\n",
      );
      process.exitCode = 1;
      return;
    }

    let existingConfig: Record<string, unknown>;
    try {
      existingConfig = await readRawConfig(projectPath);
    } catch (err) {
      process.stderr.write(
        `${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exitCode = 1;
      return;
    }

    let merged: Record<string, unknown>;
    try {
      merged = mergeConventions(existingConfig, patterns, options.force === true);
    } catch (err) {
      process.stderr.write(
        `${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exitCode = 1;
      return;
    }

    const configPath = join(projectPath, CONFIG_FILENAME);
    await writeFile(configPath, JSON.stringify(merged, null, 2) + "\n", "utf-8");
    const word = patterns.length === 1 ? "pattern" : "patterns";
    process.stdout.write(
      `Wrote ${patterns.length} inferred ${word} as conventions in ${CONFIG_FILENAME}\n`,
    );
    return;
  }

  process.stdout.write(formatPatterns(projectPath, patterns) + "\n");
}
