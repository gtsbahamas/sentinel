import { getRules } from "./registry.js";
import type { Finding, ProjectModel } from "../../model/types.js";
import type { ProjectContext } from "../context/types.js";
import type { ScanEventEmitter } from "../../dashboard/events.js";

export { registerRule, registerRules, resetRegistry } from "./registry.js";
export type { SecurityRule } from "./registry.js";

export async function runRules(
  model: ProjectModel,
  context?: ProjectContext | null,
  emitter?: ScanEventEmitter,
): Promise<Finding[]> {
  const rules = getRules().filter((r) => r.appliesTo.includes(model.meta.stack));
  const results = await Promise.all(rules.map((r) => Promise.resolve(r.check(model, context))));
  const findings = results.flat();

  if (emitter) {
    for (const f of findings) {
      emitter.emitEvent({
        type: "finding",
        data: {
          id: f.id,
          severity: f.severity,
          title: f.title,
          description: f.description,
          impact: f.impact,
          file: f.evidence[0]?.file ?? "",
          line: f.evidence[0]?.line,
          domain: f.domain,
          layer: f.layer,
          remediation: f.remediation,
        },
      });
    }
  }

  return findings;
}
