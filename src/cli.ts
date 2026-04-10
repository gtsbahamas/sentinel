#!/usr/bin/env node
import { Command } from "commander";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { runScan } from "./commands/scan.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgPath = join(__dirname, "..", "package.json");
const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));

const program = new Command();

program
  .name("sentinel")
  .description("Security assessment CLI for Next.js + Supabase codebases")
  .version(pkg.version);

program
  .command("scan")
  .description("Run Recon + Rules scan against a project")
  .argument("<path>", "Path to the project to scan")
  .option("-f, --format <format>", "Output format (terminal|json)", "terminal")
  .option("--fail-on <level>", "Exit 1 if findings at or above level")
  .action(async (path, options) => {
    const exitCode = await runScan({
      path,
      format: options.format,
      failOn: options.failOn,
    });
    process.exit(exitCode);
  });

program.parseAsync(process.argv);
