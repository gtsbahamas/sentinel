import type { Finding, ProjectModel, Severity, SecurityDomain, StackProfile } from "../../model/types.js";
import type { ProjectContext } from "../context/types.js";

export interface SecurityRule {
  id: string;
  domain: SecurityDomain;
  title: string;
  description: string;
  severity: Severity;
  appliesTo: StackProfile[];
  references: {
    cwe?: string;
    owasp?: string;
    external?: string[];
  };
  check: (model: ProjectModel, context?: ProjectContext | null) => Finding[] | Promise<Finding[]>;
}

const registry: SecurityRule[] = [];

export function registerRule(rule: SecurityRule): void {
  registry.push(rule);
}

export function registerRules(rules: SecurityRule[]): void {
  for (const rule of rules) registry.push(rule);
}

export function getRules(): readonly SecurityRule[] {
  return registry;
}

export function resetRegistry(): void {
  registry.length = 0;
}
