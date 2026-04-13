import type { Finding, ProbeConfig, ProbeRunResult, ProjectModel } from "../../model/types.js";
import { runProbeOrchestrator } from "./orchestrator.js";
import { registerProbeCheck, resetProbeRegistry } from "./checks/base.js";
import { securityHeadersCheck } from "./checks/passive/security-headers.js";
import { tlsConfigurationCheck } from "./checks/passive/tls-configuration.js";
import { endpointEnumerationCheck } from "./checks/passive/endpoint-enumeration.js";
import { responseBodySecretsCheck } from "./checks/passive/response-body-secrets.js";
import { corsConfigurationCheck } from "./checks/passive/cors-configuration.js";
import { rateLimitProbeCheck } from "./checks/standard/rate-limit-probe.js";
import { authEndpointProbeCheck } from "./checks/standard/auth-endpoint-probe.js";
import { idorProbeCheck } from "./checks/standard/idor-probe.js";
import { jwtClaimAuditCheck } from "./checks/standard/jwt-claim-audit.js";

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

function loadStandardChecks(): void {
  registerProbeCheck(rateLimitProbeCheck);
  registerProbeCheck(authEndpointProbeCheck);
  registerProbeCheck(idorProbeCheck);
  registerProbeCheck(jwtClaimAuditCheck);
}

export async function runProbe(
  model: ProjectModel,
  findings: Finding[],
  config: ProbeConfig,
  sentinelVersion = "0.2.0",
): Promise<{ result: ProbeRunResult; mergedFindings: Finding[] }> {
  resetProbeRegistry();
  loadPassiveChecks();
  loadStandardChecks();

  return runProbeOrchestrator({
    model,
    findings,
    config,
    sentinelVersion,
  });
}
