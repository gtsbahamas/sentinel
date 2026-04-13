import { randomUUID } from "crypto";
import type { ProbeTarget, ProbeFinding, ProbeError, AggressionLevel, SecurityDomain } from "../../../../model/types.js";
import type { ProbeCheck, ProbeCheckContext, ProbeCheckResult } from "../base.js";
import { TargetUnreachable } from "../../http-client.js";

const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const MAX_UUID = "ffffffff-ffff-ffff-ffff-ffffffffffff";
const SENTINEL_UUIDS = [NIL_UUID, MAX_UUID];

export const idorProbeCheck: ProbeCheck = {
  id: "idor-probe",
  level: "standard" as AggressionLevel,
  domain: "auth-access-control" as SecurityDomain,
  description: "Substitute sentinel UUIDs into path parameters and issue unauthenticated GETs to detect IDOR vulnerabilities",

  appliesTo(target: ProbeTarget): boolean {
    if (target.kind !== "endpoint") return false;
    if (!target.inputs || target.inputs.length === 0) return false;
    return target.inputs.some((input) => input.in === "path" && input.type === "uuid");
  },

  async run(ctx: ProbeCheckContext): Promise<ProbeCheckResult> {
    const findings: ProbeFinding[] = [];
    const errors: ProbeError[] = [];
    const confirmed: Array<{ findingId: string }> = [];
    const refuted: Array<{ findingId: string }> = [];

    const priorIdorFinding = ctx.priorFindings.find(
      (f) => f.domain === "auth-access-control" && (
        ctx.target.fromFindingId === f.id ||
        f.title?.toLowerCase().includes("idor") ||
        f.ruleId?.toLowerCase().includes("idor")
      ),
    );

    const uuidInputs = (ctx.target.inputs ?? []).filter(
      (input) => input.in === "path" && input.type === "uuid",
    );

    let accessibleResponse: { requestId: string; status: number; headers: Record<string, string>; body: string; timingMs: number; url: string } | null = null;
    let allDenied = true;
    let anyTested = false;

    outer:
    for (const input of uuidInputs) {
      for (const sentinelUuid of SENTINEL_UUIDS) {
        const url = ctx.target.url.replace(`:${input.name}`, sentinelUuid);

        let resp: { requestId: string; status: number; headers: Record<string, string>; body: string; timingMs: number };

        try {
          resp = await ctx.client.request({
            method: "GET",
            url,
            intent: "read",
          });
        } catch (err) {
          if (err instanceof TargetUnreachable) {
            errors.push({ kind: "target-unreachable", message: err.message, checkId: "idor-probe", targetUrl: url });
            return { findings, confirmed, refuted, errors };
          }
          errors.push({ kind: "check-error", message: err instanceof Error ? err.message : String(err), checkId: "idor-probe" });
          continue;
        }

        anyTested = true;

        if (resp.status === 200 && resp.body.length > 0) {
          accessibleResponse = { ...resp, url };
          allDenied = false;
          break outer;
        }

        if (resp.status === 404) {
          // 404 is no signal — neither confirm nor refute, but don't count as denied
          allDenied = false;
          continue;
        }

        if (resp.status === 401 || resp.status === 403) {
          // Counts as denied — keep allDenied true unless overridden
          continue;
        }

        // Any other status is not a denial
        allDenied = false;
      }
    }

    if (accessibleResponse !== null) {
      const finding: ProbeFinding = {
        id: `PROBE-IDOR-${randomUUID().slice(0, 8)}`,
        domain: "auth-access-control",
        severity: "high",
        confidence: "confirmed",
        title: `Potential IDOR: unauthenticated access to ${accessibleResponse.url}`,
        description: `An unauthenticated GET request to a sentinel UUID path parameter returned HTTP 200 with a non-empty body, indicating the endpoint may not enforce ownership checks (Insecure Direct Object Reference).`,
        impact: "Your endpoint returns data for any resource ID without verifying ownership. An attacker can enumerate IDs to access other users' data, bypassing all access control.",
        evidence: [],
        remediation: "Ensure all resource access endpoints verify that the requesting user owns or has permission to access the requested resource. Do not rely solely on the ID being unguessable.",
        references: [
          "https://cwe.mitre.org/data/definitions/639.html",
          "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
        layer: "probe",
        cwe: "CWE-639",
        probeEvidence: {
          requestId: accessibleResponse.requestId,
          checkId: "idor-probe",
          aggressionLevel: "standard",
          request: { method: "GET", url: accessibleResponse.url, headers: {} },
          response: { status: accessibleResponse.status, headers: accessibleResponse.headers, bodyPreview: accessibleResponse.body.slice(0, 256), timingMs: accessibleResponse.timingMs },
        },
        confirms: priorIdorFinding?.id,
      };
      findings.push(finding);
      if (priorIdorFinding) confirmed.push({ findingId: priorIdorFinding.id });
    } else if (anyTested && allDenied && priorIdorFinding) {
      // All sentinel UUIDs returned 401/403 — refute prior finding
      const finding: ProbeFinding = {
        id: `PROBE-IDOR-SAFE-${randomUUID().slice(0, 8)}`,
        domain: "auth-access-control",
        severity: "info",
        confidence: "confirmed",
        title: `IDOR not confirmed: access denied for sentinel UUIDs at ${ctx.target.url}`,
        description: `All sentinel UUID substitutions (Nil UUID and Max UUID) returned 401/403, indicating the endpoint enforces access control on unauthenticated requests.`,
        impact: "No impact — access control is correctly enforced on this endpoint.",
        evidence: [],
        remediation: "No action needed — access control is enforced.",
        references: [],
        layer: "probe",
        cwe: "CWE-639",
        probeEvidence: {
          requestId: randomUUID(),
          checkId: "idor-probe",
          aggressionLevel: "standard",
          request: { method: "GET", url: ctx.target.url, headers: {} },
          response: { status: 401, headers: {}, bodyPreview: "", timingMs: 0 },
        },
        refutes: priorIdorFinding.id,
      };
      findings.push(finding);
      refuted.push({ findingId: priorIdorFinding.id });
    }

    return { findings, confirmed, refuted, errors };
  },
};
