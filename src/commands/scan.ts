import { writeFile, mkdir } from "fs/promises";
import { dirname, join, resolve } from "path";
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
import { formatTerminal } from "../output/terminal.js";
import { formatJson } from "../output/json.js";
import { formatHtml } from "../output/html.js";
import { isAtOrAbove } from "../model/severity.js";
import type { Severity } from "../model/types.js";

export interface ScanOptions {
  path: string;
  format: "terminal" | "json" | "html";
  failOn?: Severity;
  outFile?: string;
}

export async function runScan(options: ScanOptions): Promise<number> {
  const config = await loadConfig(options.path);

  const reconStart = Date.now();
  const model = await runRecon(options.path, config.exclude);
  const recon_ms = Date.now() - reconStart;

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

  const rulesStart = Date.now();
  const findings = await runRules(model);
  const rules_ms = Date.now() - rulesStart;

  if (options.format === "json") {
    const body = formatJson(model, findings, { recon_ms, rules_ms });
    if (options.outFile) {
      const dest = resolve(options.outFile);
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, body, "utf-8");
      process.stdout.write(`Wrote JSON report to ${dest}\n`);
    } else {
      process.stdout.write(body);
    }
  } else if (options.format === "html") {
    const body = formatHtml(model, findings, { recon_ms, rules_ms });
    const dest = resolve(options.outFile ?? join(options.path, config.output.dir, `scan-${Date.now()}.html`));
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, body, "utf-8");
    process.stdout.write(`Wrote HTML report to ${dest}\n`);
  } else {
    process.stdout.write(formatTerminal(model, findings));
    process.stdout.write("\n");
  }

  const failOn = options.failOn ?? config.severity.failOn;
  const hasBlockingFinding = findings.some((f) => isAtOrAbove(f.severity, failOn));
  return hasBlockingFinding ? 1 : 0;
}
