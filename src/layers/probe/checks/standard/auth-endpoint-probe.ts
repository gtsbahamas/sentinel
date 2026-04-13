import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, SecurityDomain, AggressionLevel } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const AUTH_PATH_SEGMENTS = [
  "auth", "login", "signin", "sign-in", "signup", "sign-up",
  "register", "password", "forgot", "reset", "verify", "token", "session",
];

const ENUMERATION_PATTERNS = [
  /user\s+not\s+found/i,
  /no\s+account/i,
  /email\s+not\s+registered/i,
  /unknown\s+user/i,
  /account\s+does\s+not\s+exist/i,
  /no\s+such\s+user/i,
  /invalid\s+email/i,
  /email\s+address\s+not\s+found/i,
  /user\s+does\s+not\s+exist/i,
];

const STACK_TRACE_PATTERNS = [
  /at\s+\S+\s+\(\S+:\d+:\d+\)/,
  /Traceback\s+\(most\s+recent\s+call\s+last\)/i,
  /\.(ts|js):\d+/,
  /at\s+\S+\.js:\d+/,
  /Error:\s+.*\n\s+at\s+/s,
];

const MALFORMED_PAYLOADS = [
  { label: "empty-body", body: "{}", contentType: "application/json" },
  { label: "missing-fields", body: JSON.stringify({ email: "sentinel-probe@test.invalid" }), contentType: "application/json" },
  { label: "bad-types", body: JSON.stringify({ email: 12345, password: true }), contentType: "application/json" },
];

function isAuthUrl(url: string): boolean {
  const lower = url.toLowerCase();
  return AUTH_PATH_SEGMENTS.some((seg) => lower.includes(`/${seg}`) || lower.includes(`/${seg}/`));
}

export const authEndpointProbeCheck: ProbeCheck = {
  id: "auth-endpoint-probe",
  level: "standard" as AggressionLevel,
  domain: "auth-access-control" as SecurityDomain,
  description: "Send malformed payloads to auth endpoints to detect user enumeration and verbose error leakage",

  appliesTo(target: ProbeTarget): boolean {
    return target.kind === "endpoint" && target.method === "POST" && isAuthUrl(target.url);
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const priorAuthFinding = ctx.priorFindings.find(
      (f) => f.domain === "auth-access-control",
    );

    let enumerationFound = false;
    let stackTraceFound = false;

    for (const payload of MALFORMED_PAYLOADS) {
      if (enumerationFound && stackTraceFound) break;

      let resp: { requestId: string; status: number; headers: Record<string, string>; body: string; timingMs: number };

      try {
        resp = await ctx.client.request({
          method: "POST",
          url: ctx.target.url,
          headers: { "Content-Type": payload.contentType },
          body: payload.body,
          intent: "read",
        });
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "auth-endpoint-probe", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        }
        errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "auth-endpoint-probe" });
        continue;
      }

      const body = resp.body;

      if (!enumerationFound && ENUMERATION_PATTERNS.some((p) => p.test(body))) {
        enumerationFound = true;
        const finding: ProbeFinding = {
          id: `PROBE-AUTH-ENUM-${randomUUID().slice(0, 8)}`,
          domain: "auth-access-control",
          severity: "medium",
          confidence: "confirmed",
          title: `User enumeration via verbose error: ${ctx.target.url}`,
          description: `Auth endpoint returned a user-specific error message for a malformed ${payload.label} payload, allowing attackers to determine whether an account exists.`,
          evidence: [],
          remediation: "Return a generic error message (e.g. 'Invalid credentials') regardless of whether the account exists.",
          references: [
            "https://cwe.mitre.org/data/definitions/204.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
          ],
          layer: "probe",
          cwe: "CWE-204",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "auth-endpoint-probe",
            aggressionLevel: "standard",
            request: { method: "POST", url: ctx.target.url, headers: { "Content-Type": payload.contentType }, bodyPreview: payload.body },
            response: { status: resp.status, headers: resp.headers, bodyPreview: body.slice(0, 256), timingMs: resp.timingMs },
          },
          confirms: priorAuthFinding?.id,
        };
        findings.push(finding);
        if (priorAuthFinding) confirmed.push({ findingId: priorAuthFinding.id });
      }

      if (!stackTraceFound && STACK_TRACE_PATTERNS.some((p) => p.test(body))) {
        stackTraceFound = true;
        const finding: ProbeFinding = {
          id: `PROBE-AUTH-STACK-${randomUUID().slice(0, 8)}`,
          domain: "auth-access-control",
          severity: "medium",
          confidence: "confirmed",
          title: `Stack trace leakage in auth error response: ${ctx.target.url}`,
          description: `Auth endpoint returned a stack trace or internal file reference in its error response for a malformed ${payload.label} payload. This exposes internal implementation details to attackers.`,
          evidence: [],
          remediation: "Suppress stack traces and internal error details in production. Log them server-side only.",
          references: [
            "https://cwe.mitre.org/data/definitions/209.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
          ],
          layer: "probe",
          cwe: "CWE-209",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "auth-endpoint-probe",
            aggressionLevel: "standard",
            request: { method: "POST", url: ctx.target.url, headers: { "Content-Type": payload.contentType }, bodyPreview: payload.body },
            response: { status: resp.status, headers: resp.headers, bodyPreview: body.slice(0, 256), timingMs: resp.timingMs },
          },
        };
        findings.push(finding);
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
