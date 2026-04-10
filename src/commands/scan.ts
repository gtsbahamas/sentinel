import { loadConfig } from "../config.js";
import { runRecon } from "../layers/recon/index.js";
import { runRules, registerRules, resetRegistry } from "../layers/rules/index.js";
import { secretsExposureRules } from "../layers/rules/domains/secrets-exposure.js";
import { inputInjectionRules } from "../layers/rules/domains/input-injection.js";
import { authAccessControlRules } from "../layers/rules/domains/auth-access-control.js";
import { fileUploadRules } from "../layers/rules/domains/file-upload.js";
import { formatTerminal } from "../output/terminal.js";
import { formatJson } from "../output/json.js";
import { isAtOrAbove } from "../model/severity.js";
import type { Severity } from "../model/types.js";

export interface ScanOptions {
  path: string;
  format: "terminal" | "json";
  failOn?: Severity;
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

  const rulesStart = Date.now();
  const findings = await runRules(model);
  const rules_ms = Date.now() - rulesStart;

  if (options.format === "json") {
    process.stdout.write(formatJson(model, findings, { recon_ms, rules_ms }));
  } else {
    process.stdout.write(formatTerminal(model, findings));
    process.stdout.write("\n");
  }

  const failOn = options.failOn ?? config.severity.failOn;
  const hasBlockingFinding = findings.some((f) => isAtOrAbove(f.severity, failOn));
  return hasBlockingFinding ? 1 : 0;
}
