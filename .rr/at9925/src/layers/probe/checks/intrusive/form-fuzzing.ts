import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const STACK_TRACE_PATTERNS = [
  /at\s+[\w.]+\s+\(.*:\d+:\d+\)/,
  /^\s+at\s+/m,
  /Traceback\s*\(most\s*recent/i,
  /\.ts:\d+:\d+/,
  /\.js:\d+:\d+/,
];

function containsStackTrace(body: string): boolean {
  return STACK_TRACE_PATTERNS.some((pattern) => pattern.test(body));
}

function buildFuzzPayloads(): Array<{ label: string; body: string }> {
  // Truncated JSON (invalid JSON)
  const truncatedJson = '{"key": "val';

  // Unicode stress: 1000 null bytes + 500 emoji + 500 RTL markers
  const nullBytes = "\u0000".repeat(1000);
  const emoji = "😀".repeat(500);
  const rtlMarkers = "\u200F".repeat(500);
  const unicodeStress = JSON.stringify({ data: nullBytes + emoji + rtlMarkers });

  // Type mismatch
  const typeMismatch = JSON.stringify({ name: 99999, email: [1, 2, 3], active: "not-a-boolean" });

  // Empty object
  const emptyObject = "{}";

  // Oversized field: single field with 100KB string
  const oversizedField = JSON.stringify({ field: "A".repeat(100 * 1024) });

  return [
    { label: "truncated-json", body: truncatedJson },
    { label: "unicode-stress", body: unicodeStress },
    { label: "type-mismatch", body: typeMismatch },
    { label: "empty-object", body: emptyObject },
    { label: "oversized-field", body: oversizedField },
  ];
}

export const formFuzzingCheck: ProbeCheck = {
  id: "form-fuzzing",
  level: "intrusive" as AggressionLevel,
  domain: "business-logic" as SecurityDomain,
  description: "Send malformed POST bodies to detect unhandled errors and information disclosure",

  appliesTo(target: ProbeTarget): boolean {
    if (target.kind !== "endpoint") return false;
    if (target.method === "GET") return false;
    return target.method === "POST" || target.method === "PUT" || target.method === "PATCH";
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const payloads = buildFuzzPayloads();

    let foundServerError = false;
    let foundStackTrace = false;

    for (const payload of payloads) {
      let resp: { status: number; headers: Record<string, string>; body: string; timingMs: number; requestId: string };

      try {
        resp = await ctx.client.request({
          method: "POST",
          url: ctx.target.url,
          headers: { "content-type": "application/json" },
          body: payload.body,
          intent: "read",
        });
      } catch (err) {
        if (err instanceof TargetUnreachable) {
          errors.push({ kind: "target-unreachable", message: err.message, checkId: "form-fuzzing", targetUrl: ctx.target.url });
          return { findings, confirmed, refuted, errors };
        } else {
          errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "form-fuzzing" });
          return { findings, confirmed, refuted, errors };
        }
      }

      if (!foundServerError && resp.status >= 500) {
        foundServerError = true;
        findings.push({
          id: `PROBE-FUZZ-${randomUUID().slice(0, 8)}`,
          domain: "business-logic",
          severity: "medium",
          confidence: "confirmed",
          title: `Unhandled server error on malformed input: ${ctx.target.url}`,
          description: `The endpoint returned a ${resp.status} response when sent a malformed "${payload.label}" payload. This indicates the server failed to validate input before processing, potentially crashing or exposing internal state.`,
          impact: "Your endpoint crashes with a 5xx error when sent malformed input. This can be used for denial-of-service and may expose stack traces that reveal internal implementation details to attackers.",
          evidence: [],
          remediation: "Validate and sanitize all incoming request bodies before processing. Return consistent 4xx responses for malformed input rather than allowing unhandled exceptions to propagate.",
          references: [
            "https://cwe.mitre.org/data/definitions/20.html",
          ],
          layer: "probe",
          cwe: "CWE-20",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "form-fuzzing",
            aggressionLevel: "intrusive",
            request: { method: "POST", url: ctx.target.url, headers: { "content-type": "application/json" }, bodyPreview: payload.body.slice(0, 256) },
            response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
          },
        });
      }

      if (!foundStackTrace && containsStackTrace(resp.body)) {
        foundStackTrace = true;
        findings.push({
          id: `PROBE-FUZZ-${randomUUID().slice(0, 8)}`,
          domain: "business-logic",
          severity: "medium",
          confidence: "confirmed",
          title: `Stack trace leaked in error response: ${ctx.target.url}`,
          description: `The endpoint returned a response containing a stack trace when sent a malformed "${payload.label}" payload. Stack traces expose internal file paths, line numbers, and framework details that aid attackers in crafting targeted exploits.`,
          impact: "Your endpoint returns stack traces in error responses. Attackers can use file paths, library names, and line numbers to identify exactly which components to target in subsequent attacks.",
          evidence: [],
          remediation: "Configure error handlers to return generic error messages to clients. Log detailed stack traces server-side only. Never expose internal implementation details in API responses.",
          references: [
            "https://cwe.mitre.org/data/definitions/209.html",
          ],
          layer: "probe",
          cwe: "CWE-209",
          probeEvidence: {
            requestId: resp.requestId,
            checkId: "form-fuzzing",
            aggressionLevel: "intrusive",
            request: { method: "POST", url: ctx.target.url, headers: { "content-type": "application/json" }, bodyPreview: payload.body.slice(0, 256) },
            response: { status: resp.status, headers: resp.headers, bodyPreview: resp.body.slice(0, 256), timingMs: resp.timingMs },
          },
        });
      }

      if (foundServerError && foundStackTrace) break;
    }

    return { findings, confirmed, refuted, errors };
  },
};
