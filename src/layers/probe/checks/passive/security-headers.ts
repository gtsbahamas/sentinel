import { randomUUID } from "crypto";
import type { ProbeTarget, ProjectModel, ProbeFinding, ProbeError, SecurityDomain, AggressionLevel } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const EXPECTED_HEADERS: Array<{
  name: string;
  severity: "high" | "medium" | "low";
  description: string;
  cwe: string;
}> = [
  { name: "strict-transport-security", severity: "high", description: "HSTS header missing — browsers won't enforce HTTPS", cwe: "CWE-319" },
  { name: "content-security-policy", severity: "medium", description: "CSP header missing — no XSS mitigation at the browser level", cwe: "CWE-79" },
  { name: "x-frame-options", severity: "medium", description: "X-Frame-Options missing — page can be embedded in iframes (clickjacking)", cwe: "CWE-1021" },
  { name: "x-content-type-options", severity: "low", description: "X-Content-Type-Options missing — browser may MIME-sniff responses", cwe: "CWE-16" },
  { name: "referrer-policy", severity: "low", description: "Referrer-Policy missing — full URL may leak in Referer header", cwe: "CWE-200" },
  { name: "permissions-policy", severity: "low", description: "Permissions-Policy missing — browser features not explicitly restricted", cwe: "CWE-16" },
];

export const securityHeadersCheck: ProbeCheck = {
  id: "security-headers",
  level: "passive" as AggressionLevel,
  domain: "infrastructure" as SecurityDomain,
  description: "Inspect HTTP response headers for missing security headers",

  appliesTo(target: ProbeTarget): boolean {
    return target.kind === "baseline" || target.kind === "endpoint";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    try {
      const resp = await ctx.client.request({
        method: "GET",
        url: ctx.target.url,
        intent: "read",
      });

      const respHeadersLower: Record<string, string> = {};
      for (const [k, v] of Object.entries(resp.headers)) {
        respHeadersLower[k.toLowerCase()] = v;
      }

      for (const expected of EXPECTED_HEADERS) {
        const present = expected.name in respHeadersLower;

        const priorFinding = ctx.priorFindings.find(
          (f) =>
            f.domain === "infrastructure" &&
            f.title.toLowerCase().includes(expected.name.replace(/-/g, "")) ||
            f.title.toLowerCase().includes(expected.name),
        );

        if (!present) {
          const probeFinding: ProbeFinding = {
            id: `PROBE-HDR-${randomUUID().slice(0, 8)}`,
            domain: "infrastructure",
            severity: expected.severity,
            confidence: "confirmed",
            title: `Missing security header: ${expected.name}`,
            description: expected.description,
            impact: "Your server responses are missing a security header that browsers rely on to protect users. Without this header, certain classes of attacks that would otherwise be blocked can succeed.",
            evidence: [],
            remediation: `Add the ${expected.name} header to all responses`,
            references: [`https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/${expected.name}`],
            layer: "probe",
            cwe: expected.cwe,
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "security-headers",
              aggressionLevel: "passive",
              request: { method: "GET", url: ctx.target.url, headers: {} },
              response: {
                status: resp.status,
                headers: resp.headers,
                bodyPreview: resp.body.slice(0, 256),
                timingMs: resp.timingMs,
              },
            },
            confirms: priorFinding?.id,
          };

          findings.push(probeFinding);

          if (priorFinding) {
            confirmed.push({ findingId: priorFinding.id });
          }
        } else if (priorFinding) {
          refuted.push({ findingId: priorFinding.id });

          findings.push({
            id: `PROBE-HDR-${randomUUID().slice(0, 8)}`,
            domain: "infrastructure",
            severity: "info",
            confidence: "confirmed",
            title: `Security header present: ${expected.name}`,
            description: `Header ${expected.name} is set to: ${respHeadersLower[expected.name]}`,
            impact: "No impact — this security header is correctly configured.",
            evidence: [],
            remediation: "No action needed",
            references: [],
            layer: "probe",
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "security-headers",
              aggressionLevel: "passive",
              request: { method: "GET", url: ctx.target.url, headers: {} },
              response: {
                status: resp.status,
                headers: resp.headers,
                bodyPreview: resp.body.slice(0, 256),
                timingMs: resp.timingMs,
              },
            },
            refutes: priorFinding.id,
          });
        }
      }
    } catch (err) {
      if (err instanceof TargetUnreachable) {
        errors.push({ kind: "target-unreachable", message: err.message, checkId: "security-headers", targetUrl: ctx.target.url });
      } else {
        errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "security-headers" });
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
