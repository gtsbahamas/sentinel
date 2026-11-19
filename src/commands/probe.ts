import { loadConfig } from "../config.js";
import { runRecon } from "../layers/recon/index.js";
import { runRules } from "../layers/rules/index.js";
import { registerAllRules } from "./register-rules.js";
import { dropIgnoredFindings } from "../utils/ignored-findings.js";
import {
  runProbe,
  resolveAuthorization,
  loadAuthorizations,
  persistAuthorization,
  buildAuthorizationEntry,
} from "../layers/probe/index.js";
import { PROBE_CONFIG_DEFAULTS } from "../layers/probe/schema.js";
import { inferContext, readContext } from "../layers/context/index.js";
import { applyContextSuppressions } from "../layers/context/suppression.js";
import { formatTerminal } from "../output/terminal.js";
import { formatJson } from "../output/json.js";
import { isAtOrAbove } from "../model/severity.js";
import type { AggressionLevel, ProbeConfig, Severity } from "../model/types.js";

export interface ProbeOptions {
  path: string;
  target: string;
  level: AggressionLevel;
  authorize: boolean;
  format: "terminal" | "json";
  failOn?: Severity;
  allowPublic?: boolean;
  internalNetwork?: boolean;
  requestCap?: number;
  targetTimeout?: number;
}

export async function runProbeCommand(options: ProbeOptions): Promise<number> {
  const config = await loadConfig(options.path);

  const probeConfig: ProbeConfig = {
    ...PROBE_CONFIG_DEFAULTS,
    enabled: true,
    level: options.level,
    targetUrl: options.target,
    allowPublicHosts: options.allowPublic ?? false,
    allowInternalNetwork: options.internalNetwork ?? false,
    timeoutMs: options.targetTimeout ?? PROBE_CONFIG_DEFAULTS.timeoutMs,
  };

  if (options.requestCap) {
    probeConfig.requestCaps[options.level] = options.requestCap;
  }

  const existingEntries = await loadAuthorizations(options.path);
  const authResult = resolveAuthorization({
    targetUrl: options.target,
    requestedLevel: options.level,
    config: probeConfig,
    existingEntries,
    authorizeFlagPresent: options.authorize,
  });

  if (authResult.state === "denied-deny-list" || authResult.state === "denied-public" || authResult.state === "denied-internal") {
    process.stderr.write(`Authorization denied: ${authResult.reason}\n`);
    return 3;
  }

  if (authResult.state === "expired") {
    process.stderr.write(`Authorization expired for ${options.target}. Re-run with --authorize to renew.\n`);
    return 3;
  }

  if (authResult.state === "needs-prompt") {
    if (!options.authorize) {
      process.stderr.write(`No authorization for ${options.target}. Run with --authorize to grant access.\n`);
      return 3;
    }

    if (options.level === "intrusive") {
      process.stderr.write("Intrusive probing is not supported in v0.2.\n");
      return 3;
    }

    const persistLevel = options.level === "standard" ? "standard" : "passive";
    const entry = buildAuthorizationEntry(
      options.target,
      persistLevel,
      `Authorized via CLI on ${new Date().toISOString()}`,
    );
    await persistAuthorization(options.path, entry);
    process.stderr.write(`Authorization granted for ${entry.targetOrigin} at ${entry.level} level (expires ${entry.expiresAt})\n`);
  }

  process.stderr.write(`Running recon + rules...\n`);
  const model = await runRecon(options.path, config.exclude);

  // Context phase: load saved context or auto-infer (mirrors scan.ts)
  const contextFromFile = await readContext(options.path);
  const context = contextFromFile ?? (await inferContext(model));
  if (!contextFromFile) {
    process.stderr.write("No .sentinel/context.json found. Using auto-inferred context.\n");
    process.stderr.write("Run `sentinel context` to reduce false positives.\n\n");
  }

  registerAllRules();
  const ruleFindings = dropIgnoredFindings(
    await runRules(model, context),
    options.path,
    config.ignore,
  );

  process.stderr.write(`Running probe against ${options.target} (level: ${options.level})...\n`);
  const { result, mergedFindings } = await runProbe(model, ruleFindings, probeConfig);

  const allFindings = applyContextSuppressions(
    [...mergedFindings, ...result.findings],
    context,
  );

  if (options.format === "json") {
    const body = formatJson(model, allFindings, {
      recon_ms: 0,
      rules_ms: 0,
    });
    process.stdout.write(body);
  } else {
    process.stdout.write(formatTerminal(model, allFindings));
    process.stdout.write("\n" + formatProbeReport(result) + "\n");
  }

  const failOn = options.failOn ?? config.severity.failOn;
  const hasBlocking = allFindings.some((f) => isAtOrAbove(f.severity, failOn));

  if (result.cleanupObligationsFailed > 0) {
    process.stderr.write(`WARNING: ${result.cleanupObligationsFailed} cleanup obligation(s) failed\n`);
    for (const f of result.cleanupFailures) {
      process.stderr.write(`  - ${f.obligation}: ${f.error}\n`);
    }
    return 2;
  }

  return hasBlocking ? 1 : 0;
}

function formatProbeReport(result: import("../model/types.js").ProbeRunResult): string {
  return `Probe Analysis
──────────────
Target:        ${result.targetOrigin}
Level:         ${result.aggressionLevel}
Requests:      ${result.usedRequests} / ${result.requestCap}
New findings:  ${result.findings.length}
Confirmed:     ${result.confirmedFindingIds.length}
Refuted:       ${result.refutedFindingIds.length}
Errors:        ${result.errors.length}
Cleanup:       ${result.cleanupObligationsExecuted} executed, ${result.cleanupObligationsFailed} failed
Log:           ${result.probeLogPath}
Duration:      ${Math.round(result.durationMs / 1000)}s`;
}
