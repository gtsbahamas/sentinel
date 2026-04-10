import { getRules } from "./registry.js";
import type { Finding, ProjectModel } from "../../model/types.js";

export { registerRule, registerRules, resetRegistry } from "./registry.js";
export type { SecurityRule } from "./registry.js";

export async function runRules(model: ProjectModel): Promise<Finding[]> {
  const rules = getRules().filter((r) => r.appliesTo.includes(model.meta.stack));
  const results = await Promise.all(rules.map((r) => Promise.resolve(r.check(model))));
  return results.flat();
}
