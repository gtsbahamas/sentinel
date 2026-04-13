import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, SecurityDomain, AggressionLevel } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const SECRET_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium";
  cwe: string;
}> = [
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", cwe: "CWE-798" },
  { name: "AWS Secret Key", pattern: /(?:aws_secret_access_key|secret_key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/gi, severity: "critical", cwe: "CWE-798" },
  { name: "Generic API Key", pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}/gi, severity: "high", cwe: "CWE-798" },
  { name: "Private Key Block", pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g, severity: "critical", cwe: "CWE-321" },
  { name: "JWT Token", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g, severity: "medium", cwe: "CWE-200" },
  { name: "Supabase Service Role Key", pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}/g, severity: "critical", cwe: "CWE-798" },
  { name: "Generic Secret", pattern: /(?:secret|password|passwd|token)\s*[:=]\s*["'][^"']{8,}/gi, severity: "medium", cwe: "CWE-798" },
];

export const responseBodySecretsCheck: ProbeCheck = {
  id: "response-body-secrets",
  level: "passive" as AggressionLevel,
  domain: "secrets-exposure" as SecurityDomain,
  description: "Scan response bodies for accidentally exposed secrets and credentials",

  appliesTo(target: ProbeTarget): boolean {
    return target.kind === "baseline" || target.kind === "endpoint";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];

    try {
      const resp = await ctx.client.request({
        method: "GET",
        url: ctx.target.url,
        intent: "read",
      });

      const body = resp.body.slice(0, 4096);

      for (const pattern of SECRET_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        const match = pattern.pattern.exec(body);
        if (match) {
          const redactedMatch = match[0].slice(0, 8) + "..." + match[0].slice(-4);

          findings.push({
            id: `PROBE-SEC-${randomUUID().slice(0, 8)}`,
            domain: "secrets-exposure",
            severity: pattern.severity,
            confidence: "confirmed",
            title: `${pattern.name} found in response body: ${ctx.target.url}`,
            description: `Detected ${pattern.name} pattern in the response body (redacted: ${redactedMatch})`,
            impact: "Your API response contains what appears to be a secret or credential. Any client that receives this response, including browsers and third-party integrations, can extract and misuse this value.",
            evidence: [],
            remediation: "Remove secrets from response bodies. If this is an API key, rotate it immediately.",
            references: [],
            layer: "probe",
            cwe: pattern.cwe,
            probeEvidence: {
              requestId: resp.requestId,
              checkId: "response-body-secrets",
              aggressionLevel: "passive",
              request: { method: "GET", url: ctx.target.url, headers: {} },
              response: {
                status: resp.status,
                headers: resp.headers,
                bodyPreview: "[REDACTED — contains secrets]",
                timingMs: resp.timingMs,
              },
            },
          });
        }
      }
    } catch (err) {
      if (err instanceof TargetUnreachable) {
        errors.push({ kind: "target-unreachable", message: err.message, checkId: "response-body-secrets", targetUrl: ctx.target.url });
      } else {
        errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "response-body-secrets" });
      }
    }

    return { findings, confirmed: [], refuted: [], errors };
  },
};
