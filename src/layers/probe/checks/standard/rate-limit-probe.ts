import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, SecurityDomain, AggressionLevel } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const MAX_BURST_REQUESTS = 20;

export const rateLimitProbeCheck: ProbeCheck = {
  id: "rate-limit-probe",
  level: "standard" as AggressionLevel,
  domain: "api-security" as SecurityDomain,
  description: "Send up to 20 rapid GET requests to verify whether rate limiting is enforced",

  appliesTo(target: ProbeTarget): boolean {
    return target.kind === "endpoint";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const rateLimitFinding = ctx.priorFindings.find(
      (f) =>
        ctx.target.fromFindingId === f.id &&
        f.domain === "api-security",
    ) ?? ctx.priorFindings.find(
      (f) =>
        f.domain === "api-security" &&
        (f.title.toLowerCase().includes("rate limit") || f.ruleId?.toLowerCase().includes("rate")),
    );

    let lastResponse: { requestId: string; status: number; headers: Record<string, string>; body: string; timingMs: number } | null = null;
    let requestCount = 0;
    let rateLimitedAt: number | null = null;

    try {
      for (let i = 0; i < MAX_BURST_REQUESTS; i++) {
        const resp = await ctx.client.request({
          method: "GET",
          url: ctx.target.url,
          intent: "read",
        });

        requestCount++;
        lastResponse = resp;

        if (resp.status === 429) {
          rateLimitedAt = requestCount;
          break;
        }
      }
    } catch (err) {
      if (err instanceof TargetUnreachable) {
        errors.push({ kind: "target-unreachable", message: err.message, checkId: "rate-limit-probe", targetUrl: ctx.target.url });
        return { findings, confirmed, refuted, errors };
      } else {
        errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "rate-limit-probe" });
        return { findings, confirmed, refuted, errors };
      }
    }

    if (rateLimitedAt !== null && lastResponse !== null) {
      const retryAfter = lastResponse.headers["retry-after"];
      const description = `Rate limiting is active on ${ctx.target.url}. A 429 response was received after ${rateLimitedAt} request(s).${retryAfter ? ` Retry-After: ${retryAfter}` : ""}`;

      findings.push({
        id: `PROBE-RATELIMIT-${randomUUID().slice(0, 8)}`,
        domain: "api-security",
        severity: "info",
        confidence: "confirmed",
        title: `Rate limiting confirmed: ${ctx.target.url}`,
        description,
        evidence: [],
        remediation: "No action needed — rate limiting is working as expected.",
        references: [],
        layer: "probe",
        probeEvidence: {
          requestId: lastResponse.requestId,
          checkId: "rate-limit-probe",
          aggressionLevel: "standard",
          request: { method: "GET", url: ctx.target.url, headers: {} },
          response: { status: lastResponse.status, headers: lastResponse.headers, bodyPreview: lastResponse.body.slice(0, 256), timingMs: lastResponse.timingMs },
        },
        refutes: rateLimitFinding?.id,
      });

      if (rateLimitFinding) {
        refuted.push({ findingId: rateLimitFinding.id });
      }
    } else if (lastResponse !== null) {
      findings.push({
        id: `PROBE-RATELIMIT-${randomUUID().slice(0, 8)}`,
        domain: "api-security",
        severity: "medium",
        confidence: "confirmed",
        title: `No rate limiting detected: ${ctx.target.url}`,
        description: `${MAX_BURST_REQUESTS} rapid GET requests completed without receiving a 429 response. The endpoint appears to lack rate limiting.`,
        evidence: [],
        remediation: "Implement rate limiting to protect against abuse and denial-of-service attacks. Consider using token bucket, sliding window, or fixed window algorithms.",
        references: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
          "https://cwe.mitre.org/data/definitions/770.html",
        ],
        layer: "probe",
        cwe: "CWE-770",
        probeEvidence: {
          requestId: lastResponse.requestId,
          checkId: "rate-limit-probe",
          aggressionLevel: "standard",
          request: { method: "GET", url: ctx.target.url, headers: {} },
          response: { status: lastResponse.status, headers: lastResponse.headers, bodyPreview: lastResponse.body.slice(0, 256), timingMs: lastResponse.timingMs },
        },
        confirms: rateLimitFinding?.id,
      });

      if (rateLimitFinding) {
        confirmed.push({ findingId: rateLimitFinding.id });
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
