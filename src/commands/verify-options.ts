import type { SentinelConfig } from "../config.js";
import type { Severity, VerifyConfig } from "../model/types.js";

// Parsed shape of the --verify* CLI flags as commander hands them to us.
// Note: --no-dismiss arrives as { dismiss: false } per commander convention.
export interface VerifyOptions {
  verify?: boolean;
  verifyModel?: string;
  verifyMaxCost?: number;
  verifyConcurrency?: number;
  verifyMinSeverity?: Severity;
  dismiss?: boolean;
}

// Layer CLI options on top of config-file values, falling back to defaults
// (which already live in CONFIG_DEFAULTS.ai.verify, surfaced via config.ai.verify).
export function mergeVerifyConfig(
  options: VerifyOptions,
  config: SentinelConfig,
): VerifyConfig {
  const base = config.ai.verify;
  return {
    enabled: options.verify ?? base.enabled,
    // Verification reuses whichever provider the AI layer is configured for.
    provider: config.ai.provider,
    model: options.verifyModel ?? base.model,
    maxCostUsd: options.verifyMaxCost ?? base.maxCostUsd,
    concurrency: options.verifyConcurrency ?? base.concurrency,
    minSeverity: options.verifyMinSeverity ?? base.minSeverity,
    // commander: --no-dismiss → { dismiss: false } → we want keepDismissed: true.
    // Absent or true leaves keepDismissed at the configured default.
    keepDismissed: options.dismiss === false ? true : base.keepDismissed,
  };
}
