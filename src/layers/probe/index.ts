import type { Finding, ProbeConfig, ProbeRunResult, ProjectModel } from "../../model/types.js";
import { runProbeOrchestrator } from "./orchestrator.js";
import { registerProbeCheck, resetProbeRegistry } from "./checks/base.js";
import { securityHeadersCheck } from "./checks/passive/security-headers.js";
import { tlsConfigurationCheck } from "./checks/passive/tls-configuration.js";
import { endpointEnumerationCheck } from "./checks/passive/endpoint-enumeration.js";
import { responseBodySecretsCheck } from "./checks/passive/response-body-secrets.js";
import { corsConfigurationCheck } from "./checks/passive/cors-configuration.js";

export { registerProbeCheck, resetProbeRegistry } from "./checks/base.js";
export { resolveAuthorization, loadAuthorizations, persistAuthorization, buildAuthorizationEntry } from "./authorization.js";
export type { AuthorizationResolution } from "./authorization.js";

function loadPassiveChecks(): void {
  registerProbeCheck(securityHeadersCheck);
  registerProbeCheck(tlsConfigurationCheck);
  registerProbeCheck(endpointEnumerationCheck);
  registerProbeCheck(responseBodySecretsCheck);
  registerProbeCheck(corsConfigurationCheck);
}

export async function runProbe(
  model: ProjectModel,
  findings: Finding[],
  config: ProbeConfig,
  sentinelVersion = "0.2.0",
): Promise<{ result: ProbeRunResult; mergedFindings: Finding[] }> {
  resetProbeRegistry();
  loadPassiveChecks();

  return runProbeOrchestrator({
    model,
    findings,
    config,
    sentinelVersion,
  });
}
