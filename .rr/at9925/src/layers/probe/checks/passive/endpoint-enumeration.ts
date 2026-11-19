import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, SecurityDomain, AggressionLevel } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

export const endpointEnumerationCheck: ProbeCheck = {
  id: "endpoint-enumeration",
  level: "passive" as AggressionLevel,
  domain: "auth-access-control" as SecurityDomain,
  description: "Verify that endpoints requiring auth actually return 401/403 without credentials",

  appliesTo(target: ProbeTarget): boolean {
    return target.kind === "endpoint";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const method = ctx.target.method === "GET" || ctx.target.method === "HEAD"
      ? ctx.target.method
      : "HEAD";

    try {
      const resp = await ctx.client.request({
        method,
        url: ctx.target.url,
        intent: "read",
      });

      const isProtected = resp.status === 401 || resp.status === 403;
      const isAccessible = resp.status >= 200 && resp.status < 400;

      const authFinding = ctx.priorFindings.find(
        (f) =>
          f.domain === "auth-access-control" &&
          ctx.target.fromFindingId === f.id,
      );

      if (ctx.target.auth === "required" && isAccessible) {
        const finding: ProbeFinding = {
          id: `PROBE-ENUM-${randomUUID().slice(0, 8)}`,
          domain: "auth-access-control",
          severity: "high",
          confidence: "confirmed",
          title: `Endpoint accessible without credentials: ${ctx.target.url}`,
          description: `Expected 401/403 but got ${resp.status}. This endpoint was marked as requiring auth but responds to unauthenticated requests.`,
          impact: "An endpoint that should require authentication is publicly accessible. An unauthenticated attacker can access protected data or trigger privileged actions without any credentials.",
          evidence: [],
          remediation: "Add authentication middleware or check to this endpoint",
          references: [],
          layer: "probe",
          cwe: "CWE-306",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "endpoint-enumeration",
            aggressionLevel: "passive",
            request: { method, url: ctx.target.url, headers: {} },
            response: {
              status: resp.status,
              headers: resp.headers,
              bodyPreview: resp.body.slice(0, 256),
              timingMs: resp.timingMs,
            },
          },
          confirms: authFinding?.id,
        };

        findings.push(finding);
        if (authFinding) confirmed.push({ findingId: authFinding.id });
      } else if (ctx.target.auth === "unauthenticated" && isProtected && authFinding) {
        refuted.push({ findingId: authFinding.id });

        findings.push({
          id: `PROBE-ENUM-${randomUUID().slice(0, 8)}`,
          domain: "auth-access-control",
          severity: "info",
          confidence: "confirmed",
          title: `Endpoint correctly requires auth: ${ctx.target.url}`,
          description: `Got ${resp.status} without credentials — auth check is working`,
          impact: "No impact — authentication is correctly enforced on this endpoint.",
          evidence: [],
          remediation: "No action needed",
          references: [],
          layer: "probe",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "endpoint-enumeration",
            aggressionLevel: "passive",
            request: { method, url: ctx.target.url, headers: {} },
            response: {
              status: resp.status,
              headers: resp.headers,
              bodyPreview: resp.body.slice(0, 256),
              timingMs: resp.timingMs,
            },
          },
          refutes: authFinding.id,
        });
      }
    } catch (err) {
      if (err instanceof TargetUnreachable) {
        errors.push({ kind: "target-unreachable", message: err.message, checkId: "endpoint-enumeration", targetUrl: ctx.target.url });
      } else {
        errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "endpoint-enumeration" });
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
