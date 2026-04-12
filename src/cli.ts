#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { runScan } from "./commands/scan.js";
import { runDiff } from "./commands/diff.js";
import { runProbeCommand } from "./commands/probe.js";
import { runContextCommand } from "./commands/context.js";

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
  .option(
    "--ai-magic-link <glob>",
    "Glob for endpoints protected by unguessable URL tokens (repeatable)",
    (val: string, prev: string[] = []) => [...prev, val],
    [] as string[],
  )
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
      aiMagicLinkRoutes: options.aiMagicLink,
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

program
  .command("probe")
  .description("Run Recon + Rules + Probe against a running application")
  .argument("<path>", "Path to the project to scan")
  .requiredOption("--target <url>", "Running application URL (scheme://host[:port])")
  .option("--level <level>", "Aggression level (passive|standard|intrusive)", "passive")
  .option("--authorize", "Grant authorization for this target")
  .option("-f, --format <format>", "Output format (terminal|json)", "terminal")
  .option("--fail-on <level>", "Exit 1 if findings at or above level")
  .option("--allow-public", "Allow public TLD targets")
  .option("--internal-network", "Allow RFC1918 targets")
  .option("--request-cap <n>", "Override default request cap", parseInt)
  .option("--target-timeout <ms>", "Per-request timeout in ms", parseInt)
  .action(async (path, options) => {
    const exitCode = await runProbeCommand({
      path,
      target: options.target,
      level: options.level,
      authorize: !!options.authorize,
      format: options.format,
      failOn: options.failOn,
      allowPublic: options.allowPublic,
      internalNetwork: options.internalNetwork,
      requestCap: options.requestCap,
      targetTimeout: options.targetTimeout,
    });
    exitAfterDrain(exitCode);
  });

program
  .command("context")
  .description("Generate or display project context for smarter scanning")
  .argument("<path>", "Path to the project")
  .option("--show", "Display current context without regenerating")
  .option("--accept-defaults", "Accept all auto-inferred values without prompting")
  .option("--only <sections>", "Regenerate only specific sections (comma-separated)")
  .action(async (path, options) => {
    const exitCode = await runContextCommand({
      path,
      show: options.show,
      acceptDefaults: options.acceptDefaults,
      only: options.only,
    });
    exitAfterDrain(exitCode);
  });

program.parseAsync(process.argv);
