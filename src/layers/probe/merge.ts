import type { Finding, ProbeFinding, ProbeEvidence } from "../../model/types.js";
import type { ProbeCheckResult } from "./checks/base.js";

export interface MergeResult {
  findings: Finding[];
  newProbeFindings: ProbeFinding[];
  confirmedIds: string[];
  refutedIds: string[];
}

export function mergeProbeResults(
  existingFindings: Finding[],
  checkResults: ProbeCheckResult[],
): MergeResult {
  const confirmedIds: string[] = [];
  const refutedIds: string[] = [];
  const newProbeFindings: ProbeFinding[] = [];

  const confirmMap = new Map<string, ProbeEvidence>();
  const refuteMap = new Map<string, ProbeEvidence>();

  for (const result of checkResults) {
    for (const c of result.confirmed) {
      const probeFinding = result.findings.find((f) => f.confirms === c.findingId);
      if (probeFinding) {
        confirmMap.set(c.findingId, probeFinding.probeEvidence);
      }
    }

    for (const r of result.refuted) {
      const probeFinding = result.findings.find((f) => f.refutes === r.findingId);
      if (probeFinding) {
        refuteMap.set(r.findingId, probeFinding.probeEvidence);
      }
    }

    for (const f of result.findings) {
      if (!f.confirms && !f.refutes) {
        newProbeFindings.push(f);
      }
    }
  }

  const merged = existingFindings.map((f) => {
    if (confirmMap.has(f.id)) {
      confirmedIds.push(f.id);
      return {
        ...f,
        confidence: "confirmed" as const,
        probeEvidence: confirmMap.get(f.id),
      };
    }
    if (refuteMap.has(f.id)) {
      refutedIds.push(f.id);
      return {
        ...f,
        confidence: "low" as const,
        probeEvidence: refuteMap.get(f.id),
        refutedByProbe: true,
      };
    }
    return f;
  });

  return {
    findings: merged,
    newProbeFindings,
    confirmedIds,
    refutedIds,
  };
}
