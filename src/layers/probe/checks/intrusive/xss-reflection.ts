import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

function generateMarker(): string {
  const nonce = randomUUID().slice(0, 8);
  return `<sentinel-marker-${nonce}/>`;
}

export const xssReflectionCheck: ProbeCheck = {
  id: "xss-reflection",
  level: "intrusive" as AggressionLevel,
  domain: "input-injection" as SecurityDomain,
  description: "Inject benign marker strings into query and body inputs to detect unescaped XSS reflection",

  appliesTo(target: ProbeTarget): boolean {
    if (target.kind !== "endpoint") return false;
    if (!target.inputs || target.inputs.length === 0) return false;
    return target.inputs.some((inp) => inp.in === "query" || inp.in === "body");
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const priorXssFinding = ctx.priorFindings.find(
      (f) =>
        ctx.target.fromFindingId === f.id &&
        f.domain === "input-injection",
    ) ?? ctx.priorFindings.find(
      (f) =>
        f.domain === "input-injection" &&
        (f.title.toLowerCase().includes("xss") || f.ruleId?.toLowerCase().includes("xss")),
    );

    const inputs = ctx.target.inputs ?? [];
    const queryInputs = inputs.filter((inp) => inp.in === "query");
    const bodyInputs = inputs.filter((inp) => inp.in === "body");

    // Check query inputs
    for (const input of queryInputs) {
      const marker = generateMarker();
      const urlObj = new URL(ctx.target.url);
      urlObj.searchParams.set(input.name, marker);
      const testUrl = urlObj.toString();

      let resp: { status: number; headers: Record<string, string>; body: string; timingMs: number; requestId: string };

      try {
        resp = await ctx.client.request({
          method: "GET",
          url: testUrl,
          intent: "read",
        });
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "xss-reflection", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        } else {
          errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "xss-reflection" });
          return { findings, confirmed, refuted, errors };
        }
      }

      if (resp.body.includes(marker)) {
        const description = `The endpoint at ${ctx.target.url} reflects the value of query parameter "${input.name}" unescaped in the response body. An attacker could inject malicious scripts that execute in a victim's browser.`;

        findings.push({
          id: `PROBE-XSS-${randomUUID().slice(0, 8)}`,
          domain: "input-injection",
          severity: "high",
          confidence: "confirmed",
          title: `XSS reflection detected via query parameter: ${input.name}`,
          description,
          evidence: [],
          remediation: "Escape all user-supplied input before rendering it in HTML responses. Use a context-aware escaping library and consider implementing a Content Security Policy (CSP).",
          references: [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
          ],
          layer: "probe",
          cwe: "CWE-79",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "xss-reflection",
            aggressionLevel: "intrusive",
            request: { method: "GET", url: testUrl, headers: {} },
            response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
          },
          confirms: priorXssFinding?.id,
        });

        if (priorXssFinding) {
          confirmed.push({ findingId: priorXssFinding.id });
        }

        return { findings, confirmed, refuted, errors };
      }
    }

    // Check body inputs
    for (const input of bodyInputs) {
      const marker = generateMarker();
      const requestBody = JSON.stringify({ [input.name]: marker });

      let resp: { status: number; headers: Record<string, string>; body: string; timingMs: number; requestId: string };

      try {
        resp = await ctx.client.request({
          method: "POST",
          url: ctx.target.url,
          headers: { "content-type": "application/json" },
          body: requestBody,
          intent: "read",
        });
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "xss-reflection", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        } else {
          errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "xss-reflection" });
          return { findings, confirmed, refuted, errors };
        }
      }

      if (resp.body.includes(marker)) {
        const description = `The endpoint at ${ctx.target.url} reflects the value of body parameter "${input.name}" unescaped in the response body. An attacker could inject malicious scripts that execute in a victim's browser.`;

        findings.push({
          id: `PROBE-XSS-${randomUUID().slice(0, 8)}`,
          domain: "input-injection",
          severity: "high",
          confidence: "confirmed",
          title: `XSS reflection detected via body parameter: ${input.name}`,
          description,
          evidence: [],
          remediation: "Escape all user-supplied input before rendering it in HTML responses. Use a context-aware escaping library and consider implementing a Content Security Policy (CSP).",
          references: [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cwe.mitre.org/data/definitions/79.html",
          ],
          layer: "probe",
          cwe: "CWE-79",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "xss-reflection",
            aggressionLevel: "intrusive",
            request: { method: "POST", url: ctx.target.url, headers: { "content-type": "application/json" }, bodyPreview: requestBody.slice(0, 256) },
            response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
          },
          confirms: priorXssFinding?.id,
        });

        if (priorXssFinding) {
          confirmed.push({ findingId: priorXssFinding.id });
        }

        return { findings, confirmed, refuted, errors };
      }
    }

    return { findings, confirmed, refuted, errors };
  },
};
