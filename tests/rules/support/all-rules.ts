import { realpathSync } from "fs";
import { loadConfig } from "../../../src/config.js";
import { runRecon } from "../../../src/layers/recon/index.js";
import { registerRules, resetRegistry } from "../../../src/layers/rules/index.js";
import { secretsExposureRules } from "../../../src/layers/rules/domains/secrets-exposure.js";
import { inputInjectionRules } from "../../../src/layers/rules/domains/input-injection.js";
import { authAccessControlRules } from "../../../src/layers/rules/domains/auth-access-control.js";
import { fileUploadRules } from "../../../src/layers/rules/domains/file-upload.js";
import { supplyChainRules } from "../../../src/layers/rules/domains/supply-chain.js";
import { repoIntegrityRules, resetRepoIntegrityCache } from "../../../src/layers/rules/domains/repo-integrity.js";
import { cryptographyRules } from "../../../src/layers/rules/domains/cryptography.js";
import { loggingMonitoringRules } from "../../../src/layers/rules/domains/logging-monitoring.js";
import { apiSecurityRules } from "../../../src/layers/rules/domains/api-security.js";
import { businessLogicRules } from "../../../src/layers/rules/domains/business-logic.js";
import { infrastructureRules } from "../../../src/layers/rules/domains/infrastructure.js";
import { llmFeatureRules } from "../../../src/layers/rules/domains/llm-features.js";
import { pythonFrameworkRules } from "../../../src/layers/rules/domains/python-framework.js";
import type { Finding, ProjectModel } from "../../../src/model/types.js";

/** The same thirteen rule sets `sentinel scan` registers, in the same order. */
export const ALL_RULE_SETS = [
  secretsExposureRules,
  inputInjectionRules,
  authAccessControlRules,
  fileUploadRules,
  supplyChainRules,
  repoIntegrityRules,
  cryptographyRules,
  loggingMonitoringRules,
  apiSecurityRules,
  businessLogicRules,
  infrastructureRules,
  llmFeatureRules,
  pythonFrameworkRules,
];

export function registerAllRuleSets(): void {
  resetRegistry();
  for (const set of ALL_RULE_SETS) registerRules(set);
  resetRepoIntegrityCache();
}

/** Recon a project directory the way `sentinel scan` does, with every rule set registered. */
export async function reconWithAllRules(dir: string): Promise<{ model: ProjectModel; root: string }> {
  const root = realpathSync(dir);
  const config = await loadConfig(root);
  const model = await runRecon(root, config.exclude);
  registerAllRuleSets();
  return { model, root };
}

export interface FindingKey {
  ruleId: string;
  severity: string;
  title: string;
  file: string;
  line: number | null;
}

/** A finding reduced to what a reader sees, with the project root stripped from every path. */
export function findingKey(f: Finding, root: string): FindingKey {
  const strip = (s: string) => s.split(root + "/").join("").split(root).join(".");
  return {
    ruleId: f.ruleId ?? "",
    severity: f.severity,
    title: strip(f.title),
    file: strip(f.evidence[0]?.file ?? ""),
    line: f.evidence[0]?.line ?? null,
  };
}

export function sortKeys(keys: FindingKey[]): FindingKey[] {
  const order = (k: FindingKey) => `${k.ruleId}\u0000${k.file}\u0000${k.line ?? 0}\u0000${k.title}\u0000${k.severity}`;
  return [...keys].sort((a, b) => (order(a) < order(b) ? -1 : order(a) > order(b) ? 1 : 0));
}
