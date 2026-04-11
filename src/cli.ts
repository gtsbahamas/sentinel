#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { runScan } from "./commands/scan.js";
import { runDiff } from "./commands/diff.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgPath = join(__dirname, "..", "package.json");
const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));

const program = new Command();

program
  .name("sentinel")
  .description("Security assessment CLI for Next.js + Supabase codebases")
  .version(pkg.version);

// Deferred exit: set process.exitCode and let Node drain stdout naturally.
// Using process.exit() after a large stdout.write() can truncate output
// at the pipe buffer boundary (~64KB).
function exitAfterDrain(code: number): void {
  process.exitCode = code;
}

program
  .command("scan")
  .description("Run Recon + Rules (+ AI) scan against a project")
  .argument("<path>", "Path to the project to scan")
  .option("-f, --format <format>", "Output format (terminal|json|html)", "terminal")
  .option("-o, --out <file>", "Write report to file instead of stdout")
  .option("--fail-on <level>", "Exit 1 if findings at or above level")
  .option("--ai", "Enable AI layer (opt-in)")
  .option("--ai-deep", "Enable Stage A project-wide risk pass")
  .option("--ai-dry-run", "Estimate cost only, make no API calls")
  .option("--ai-provider <name>", "AI provider (anthropic|openai|mock)")
  .option("--ai-model <id>", "AI model id")
  .option("--ai-max-cost <usd>", "Hard budget cap in USD", parseFloat)
  .option("--ai-concurrency <n>", "Parallel endpoint analyses", parseInt)
  .action(async (path, options) => {
    const exitCode = await runScan({
      path,
      format: options.format,
      failOn: options.failOn,
      outFile: options.out,
      ai: options.ai,
      aiDeep: options.aiDeep,
      aiDryRun: options.aiDryRun,
      aiProvider: options.aiProvider,
      aiModel: options.aiModel,
      aiMaxCost: options.aiMaxCost,
      aiConcurrency: options.aiConcurrency,
    });
    exitAfterDrain(exitCode);
  });

program
  .command("diff")
  .description("Diff two sentinel JSON reports — shows new, resolved, and unchanged findings")
  .argument("<baseline>", "Path to baseline JSON report")
  .argument("<current>", "Path to current JSON report")
  .option("-f, --format <format>", "Output format (terminal|json)", "terminal")
  .option("--fail-on <level>", "Exit 1 if NEW findings at or above level")
  .action(async (baseline, current, options) => {
    const exitCode = await runDiff({
      baseline,
      current,
      format: options.format,
      failOn: options.failOn,
    });
    exitAfterDrain(exitCode);
  });

program.parseAsync(process.argv);
