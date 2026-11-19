import { getRules } from "./registry.js";
import { splitIgnored } from "./ignore.js";
import type { Finding, IgnoredFinding, ProjectModel } from "../../model/types.js";
import type { ProjectContext } from "../context/types.js";
import type { ScanEventEmitter } from "../../dashboard/events.js";

export { registerRule, registerRules, resetRegistry } from "./registry.js";
export type { SecurityRule } from "./registry.js";

export interface RuleRunResult {
  /** Findings that alarm. */
  findings: Finding[];
  /** Findings a `sentinel:ignore` comment covers. Reports count and list these; they never fail a scan. */
  ignored: IgnoredFinding[];
}

/**
 * Run every registered rule for the model's stack. This is what a command
 * that reports to a person calls: it must pass `ignored` on to its output so
 * an ignored finding is still seen.
 */
export async function runRulesWithIgnored(
  model: ProjectModel,
  context?: ProjectContext | null,
  _emitter?: ScanEventEmitter,
): Promise<RuleRunResult> {
  const rules = getRules().filter((r) => r.appliesTo.includes(model.meta.stack));
  const results = await Promise.all(rules.map((r) => Promise.resolve(r.check(model, context))));

  // A finding normally carries its rule id; when one does not, it belongs to
  // the rule whose check() returned it.
  const producedBy = new Map<Finding, string>();
  results.forEach((list, i) => {
    for (const f of list) producedBy.set(f, rules[i].id);
  });

  // NOTE: findings are NOT emitted here. The scan command applies context
  // suppressions first, then emits the filtered set via emitFindings().

  return splitIgnored(results.flat(), model.meta.path, (f) => f.ruleId ?? producedBy.get(f));
}

/** The active findings only. Use runRulesWithIgnored() anywhere the result is shown to a person. */
export async function runRules(
  model: ProjectModel,
  context?: ProjectContext | null,
  emitter?: ScanEventEmitter,
): Promise<Finding[]> {
  return (await runRulesWithIgnored(model, context, emitter)).findings;
}
