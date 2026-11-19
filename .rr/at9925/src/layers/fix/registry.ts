import type { Fixer } from "./types.js";
import { crypto001Fixer } from "./deterministic/crypto-001.js";
import { crypto002Fixer } from "./deterministic/crypto-002.js";
import { log005Fixer } from "./deterministic/log-005.js";
import { infra001Fixer } from "./deterministic/infra-001.js";
import { infra006Fixer } from "./deterministic/infra-006.js";

/**
 * The canonical list of deterministic fixers.
 *
 * Adding a new deterministic fixer? Append it here AND make sure
 * `registerAllFixers()` in `src/commands/fix.ts` references the same set
 * (or imports from this list).
 */
export const DETERMINISTIC_FIXERS: readonly Fixer[] = [
  crypto001Fixer,
  crypto002Fixer,
  log005Fixer,
  infra001Fixer,
  infra006Fixer,
];

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
