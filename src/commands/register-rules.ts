import { getRules, registerRules, resetRegistry } from "../layers/rules/registry.js";
import { secretsExposureRules } from "../layers/rules/domains/secrets-exposure.js";
import { inputInjectionRules } from "../layers/rules/domains/input-injection.js";
import { authAccessControlRules } from "../layers/rules/domains/auth-access-control.js";
import { fileUploadRules } from "../layers/rules/domains/file-upload.js";
import { supplyChainRules } from "../layers/rules/domains/supply-chain.js";
import { repoIntegrityRules, resetRepoIntegrityCache } from "../layers/rules/domains/repo-integrity.js";
import { cryptographyRules } from "../layers/rules/domains/cryptography.js";
import { loggingMonitoringRules } from "../layers/rules/domains/logging-monitoring.js";
import { apiSecurityRules } from "../layers/rules/domains/api-security.js";
import { businessLogicRules } from "../layers/rules/domains/business-logic.js";
import { infrastructureRules } from "../layers/rules/domains/infrastructure.js";
import { llmFeatureRules } from "../layers/rules/domains/llm-features.js";
import { pythonFrameworkRules } from "../layers/rules/domains/python-framework.js";

/**
 * Fill the rule registry with every rule the scanner ships. The one list of
 * rule sets: scan, probe, fix and `scan --list-rules` all call this, so the
 * catalog a user is shown is the catalog that runs.
 */
export function registerAllRules(): void {
  resetRegistry();
  registerRules(secretsExposureRules);
  registerRules(inputInjectionRules);
  registerRules(authAccessControlRules);
  registerRules(fileUploadRules);
  registerRules(supplyChainRules);
  registerRules(repoIntegrityRules);
  // Memoized whole-tree walk must not survive into the next scan in this process.
  resetRepoIntegrityCache();
  registerRules(cryptographyRules);
  registerRules(loggingMonitoringRules);
  registerRules(apiSecurityRules);
  registerRules(businessLogicRules);
  registerRules(infrastructureRules);
  registerRules(llmFeatureRules);
  registerRules(pythonFrameworkRules);
}

/**
 * The rule catalog for `scan --list-rules`: one line per rule (id, severity,
 * title) for a terminal, or the same rows plus domain as JSON.
 */
export function formatRuleCatalog(format: "terminal" | "json" | "html"): string {
  registerAllRules();
  const rules = getRules();
  if (format === "json") {
    return (
      JSON.stringify(
        rules.map((r) => ({ id: r.id, severity: r.severity, domain: r.domain, title: r.title })),
        null,
        2,
      ) + "\n"
    );
  }
  const idWidth = Math.max(...rules.map((r) => r.id.length));
  const severityWidth = Math.max(...rules.map((r) => r.severity.length));
  return rules
    .map((r) => `${r.id.padEnd(idWidth)}  ${r.severity.padEnd(severityWidth)}  ${r.title}\n`)
    .join("");
}
