import { getRules } from "./registry.js";
import type { Finding, ProjectModel } from "../../model/types.js";
import type { ProjectContext } from "../context/types.js";
import type { ScanEventEmitter } from "../../dashboard/events.js";

export { registerRule, registerRules, resetRegistry } from "./registry.js";
export type { SecurityRule } from "./registry.js";

export async function runRules(
  model: ProjectModel,
  context?: ProjectContext | null,
  _emitter?: ScanEventEmitter,
): Promise<Finding[]> {
  const rules = getRules().filter((r) => r.appliesTo.includes(model.meta.stack));
  const results = await Promise.all(rules.map((r) => Promise.resolve(r.check(model, context))));
  const findings = results.flat();

  // NOTE: findings are NOT emitted here. The scan command applies context
  // suppressions first, then emits the filtered set via emitFindings().

  return findings;
}
