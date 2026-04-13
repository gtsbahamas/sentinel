import { describe, it, expect } from "vitest";
import { crypto001Fixer } from "../../../../src/layers/fix/deterministic/crypto-001.js";
import type { Finding } from "../../../../src/model/types.js";

function makeFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: "test-finding-1",
    ruleId: "CRYPTO-001",
    domain: "cryptography",
    severity: "high",
    confidence: "confirmed",
    title: "Insecure Random Number Generation",
    description: "Math.random() used in security context",
    impact: "Predictable values may be exploited",
    evidence: [{ file: "src/utils/token.ts", line: 10 }],
    remediation: "Use crypto.randomUUID() instead",
    references: [],
    layer: "rules",
    ...overrides,
  };
}

describe("crypto001Fixer", () => {
  it("has correct ruleId and type", () => {
    expect(crypto001Fixer.ruleId).toBe("CRYPTO-001");
    expect(crypto001Fixer.type).toBe("deterministic");
  });

  it("returns null when no Math.random() found", () => {
    const content = `import { randomUUID } from "node:crypto";\nconst id = randomUUID();`;
    const result = crypto001Fixer.apply!(content, makeFinding());
    expect(result).toBeNull();
  });

  it("replaces Math.random().toString(36).substring(...) with crypto.randomUUID()", () => {
    const content = `const token = Math.random().toString(36).substring(2);`;
    const result = crypto001Fixer.apply!(content, makeFinding());
    expect(result).not.toBeNull();
    expect(result).not.toContain("Math.random()");
    expect(result).toContain("crypto.randomUUID()");
  });

  it("replaces bare Math.random() with crypto.randomUUID()", () => {
    const content = `const val = Math.random();`;
    const result = crypto001Fixer.apply!(content, makeFinding());
    expect(result).not.toBeNull();
    expect(result).not.toContain("Math.random()");
    expect(result).toContain("crypto.randomUUID()");
  });

  it("adds crypto import when not present", () => {
    const content = `const id = Math.random().toString(36).substring(2);`;
    const result = crypto001Fixer.apply!(content, makeFinding());
    expect(result).not.toBeNull();
    expect(result).toContain(`import { randomUUID } from "node:crypto"`);
  });

  it("does not duplicate the crypto import when already present", () => {
    const content = [
      `import { randomUUID } from "node:crypto";`,
      `const id = Math.random().toString(36).substring(2);`,
    ].join("\n");
    const result = crypto001Fixer.apply!(content, makeFinding());
    expect(result).not.toBeNull();
    const importCount = (result!.match(/import \{ randomUUID \} from "node:crypto"/g) ?? []).length;
    expect(importCount).toBe(1);
  });

  it("is idempotent — running twice produces the same result", () => {
    const content = `const id = Math.random().toString(36).substring(2);`;
    const first = crypto001Fixer.apply!(content, makeFinding())!;
    const second = crypto001Fixer.apply!(first, makeFinding());
    expect(second).toBeNull(); // no Math.random() remains, so fixer has nothing to do
  });

  it("handles multiple Math.random() calls in the same file", () => {
    const content = [
      `const a = Math.random().toString(36).substring(2);`,
      `const b = Math.random();`,
    ].join("\n");
    const result = crypto001Fixer.apply!(content, makeFinding());
    expect(result).not.toBeNull();
    expect(result).not.toContain("Math.random()");
    // Import should only appear once
    const importCount = (result!.match(/import \{ randomUUID \} from "node:crypto"/g) ?? []).length;
    expect(importCount).toBe(1);
  });
});
