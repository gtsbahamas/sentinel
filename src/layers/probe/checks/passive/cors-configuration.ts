import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, SecurityDomain, AggressionLevel } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const PROBE_ORIGIN = "https://sentinel-cors-probe.example.com";

export const corsConfigurationCheck: ProbeCheck = {
  id: "cors-configuration",
  level: "passive" as AggressionLevel,
  domain: "api-security" as SecurityDomain,
  description: "Send OPTIONS preflight with a probe Origin to check CORS configuration",

  appliesTo(target: ProbeTarget): boolean {
    return target.kind === "endpoint";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    try {
      const resp = await ctx.client.request({
        method: "OPTIONS",
        url: ctx.target.url,
        headers: {
          Origin: PROBE_ORIGIN,
          "Access-Control-Request-Method": "POST",
        },
        intent: "read",
      });

      const acao = resp.headers["access-control-allow-origin"] ?? "";
      const acac = resp.headers["access-control-allow-credentials"] ?? "";

      const isWildcard = acao === "*";
      const reflectsOrigin = acao === PROBE_ORIGIN;
      const allowsCredentials = acac.toLowerCase() === "true";

      const corsFinding = ctx.priorFindings.find(
        (f) =>
          f.domain === "api-security" &&
          (f.title.toLowerCase().includes("cors") || f.ruleId?.includes("CORS")),
      );

      if (isWildcard && allowsCredentials) {
        findings.push(makeFinding(
          "critical",
          `Wildcard CORS with credentials on ${ctx.target.url}`,
          "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true. Browsers will block this, but the misconfiguration indicates a broken CORS setup that may fall through to origin reflection.",
          resp, ctx, corsFinding?.id,
        ));
        if (corsFinding) confirmed.push({ findingId: corsFinding.id });
      } else if (reflectsOrigin) {
        findings.push(makeFinding(
          allowsCredentials ? "high" : "medium",
          `CORS reflects arbitrary origin${allowsCredentials ? " with credentials" : ""}: ${ctx.target.url}`,
          `Server reflected the probe origin (${PROBE_ORIGIN}) in Access-Control-Allow-Origin${allowsCredentials ? " and allows credentials — any site can make authenticated cross-origin requests" : ""}`,
          resp, ctx, corsFinding?.id,
        ));
        if (corsFinding) confirmed.push({ findingId: corsFinding.id });
      } else if (isWildcard) {
        findings.push(makeFinding(
          "low",
          `Wildcard CORS (no credentials): ${ctx.target.url}`,
          "Access-Control-Allow-Origin: * without credentials. Low risk for public APIs, but should be reviewed for endpoints that handle sensitive data.",
          resp, ctx, corsFinding?.id,
        ));
        if (corsFinding) confirmed.push({ findingId: corsFinding.id });
      } else if (corsFinding && !reflectsOrigin && !isWildcard) {
        refuted.push({ findingId: corsFinding.id });
        findings.push({
          id: `PROBE-CORS-${randomUUID().slice(0, 8)}`,
          domain: "api-security",
          severity: "info",
          confidence: "confirmed",
          title: `CORS correctly configured: ${ctx.target.url}`,
          description: `Probe origin was not reflected. ACAO: ${acao || "(not set)"}`,
          evidence: [],
          remediation: "No action needed",
          references: [],
          layer: "probe",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "cors-configuration",
            aggressionLevel: "passive",
            request: { method: "OPTIONS", url: ctx.target.url, headers: { Origin: PROBE_ORIGIN } },
            response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
          },
          refutes: corsFinding.id,
        });
      }
    } catch (err) {
      if (err instanceof TargetUnreachable) {
        errors.push({ kind: "target-unreachable", message: err.message, checkId: "cors-configuration", targetUrl: ctx.target.url });
      } else {
        errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "cors-configuration" });
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};

function makeFinding(
  severity: "critical" | "high" | "medium" | "low",
  title: string,
  description: string,
  resp: { requestId: string; status: number; headers: Record<string, string>; body: string; timingMs: number },
  ctx: ProbeCheckContext,
  confirmsId?: string,
): ProbeFinding {
  return {
    id: `PROBE-CORS-${randomUUID().slice(0, 8)}`,
    domain: "api-security",
    severity,
    confidence: "confirmed",
    title,
    description,
    evidence: [],
    remediation: "Configure CORS to allow only trusted origins. Avoid wildcard (*) with credentials.",
    references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
    layer: "probe",
    cwe: "CWE-942",
    probeEvidence: {
      requestId: resp.requestId,
      checkId: "cors-configuration",
      aggressionLevel: "passive",
      request: {
        method: "OPTIONS",
        url: ctx.target.url,
        headers: { Origin: PROBE_ORIGIN, "Access-Control-Request-Method": "POST" },
      },
      response: {
        status: resp.status,
        headers: resp.headers,
        bodyPreview: resp.body.slice(0, 256),
        timingMs: resp.timingMs,
      },
    },
    confirms: confirmsId,
  };
}
