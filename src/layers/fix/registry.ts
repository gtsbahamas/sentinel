import type { Fixer } from "./types.js";

const registry = new Map<string, Fixer>();

export function registerFixer(fixer: Fixer): void {
  registry.set(fixer.ruleId, fixer);
}

export function getFixer(ruleId: string): Fixer | undefined {
  return registry.get(ruleId);
}

export function getAll(): ReadonlyMap<string, Fixer> {
  return registry;
}

export function resetFixerRegistry(): void {
  registry.clear();
}
