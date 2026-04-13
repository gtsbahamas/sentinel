import { describe, it, expect, beforeEach } from "vitest";
import { registerFixer, getFixer, getAll, resetFixerRegistry } from "../../../src/layers/fix/registry.js";
import type { Fixer } from "../../../src/layers/fix/types.js";
import type { Finding } from "../../../src/model/types.js";

beforeEach(() => {
  resetFixerRegistry();
});

describe("registerFixer / getFixer", () => {
  it("registers a deterministic fixer and retrieves it", () => {
    const fixer: Fixer = {
      ruleId: "CRYPTO-001",
      type: "deterministic",
      apply: (content: string, _finding: Finding) => content.replace("md5", "sha256"),
    };

    registerFixer(fixer);
    const result = getFixer("CRYPTO-001");

    expect(result).toBeDefined();
    expect(result?.ruleId).toBe("CRYPTO-001");
    expect(result?.type).toBe("deterministic");
    expect(typeof result?.apply).toBe("function");
  });

  it("registers an AI fixer and retrieves it", () => {
    const fixer: Fixer = {
      ruleId: "INFRA-006",
      type: "ai",
      aiPromptId: "fix-infra-006",
    };

    registerFixer(fixer);
    const result = getFixer("INFRA-006");

    expect(result).toBeDefined();
    expect(result?.ruleId).toBe("INFRA-006");
    expect(result?.type).toBe("ai");
    expect(result?.aiPromptId).toBe("fix-infra-006");
  });

  it("returns undefined for unregistered rule id", () => {
    expect(getFixer("NOT-A-RULE")).toBeUndefined();
  });
});

describe("getAll", () => {
  it("returns all registered fixers", () => {
    const fixerA: Fixer = { ruleId: "CRYPTO-001", type: "deterministic" };
    const fixerB: Fixer = { ruleId: "LOG-005", type: "ai", aiPromptId: "fix-log-005" };

    registerFixer(fixerA);
    registerFixer(fixerB);

    const all = getAll();
    expect(all.size).toBe(2);
    expect(all.get("CRYPTO-001")).toEqual(fixerA);
    expect(all.get("LOG-005")).toEqual(fixerB);
  });

  it("returns empty map when nothing registered", () => {
    expect(getAll().size).toBe(0);
  });
});

describe("resetFixerRegistry", () => {
  it("clears all registered fixers", () => {
    registerFixer({ ruleId: "CRYPTO-001", type: "deterministic" });
    registerFixer({ ruleId: "CRYPTO-002", type: "deterministic" });
    expect(getAll().size).toBe(2);

    resetFixerRegistry();
    expect(getAll().size).toBe(0);
    expect(getFixer("CRYPTO-001")).toBeUndefined();
  });
});
