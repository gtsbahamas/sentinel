import { describe, it, expect } from "vitest";
import { crypto002Fixer } from "../../../../src/layers/fix/deterministic/crypto-002.js";
import type { Finding } from "../../../../src/model/types.js";

const stubFinding = { id: "f1" } as Finding;

describe("crypto002Fixer", () => {
  it("has correct ruleId and type", () => {
    expect(crypto002Fixer.ruleId).toBe("CRYPTO-002");
    expect(crypto002Fixer.type).toBe("deterministic");
  });

  it("replaces single-quoted md5 with sha256", () => {
    const input = "const hash = createHash('md5');";
    const result = crypto002Fixer.apply!(input, stubFinding);
    expect(result).toBe("const hash = createHash('sha256');");
  });

  it("replaces double-quoted md5 with sha256", () => {
    const input = 'const hash = createHash("md5");';
    const result = crypto002Fixer.apply!(input, stubFinding);
    expect(result).toBe('const hash = createHash("sha256");');
  });

  it("replaces all occurrences in a file with multiple md5 calls", () => {
    const input = [
      "const a = createHash('md5');",
      "const b = createHash(\"md5\");",
    ].join("\n");
    const result = crypto002Fixer.apply!(input, stubFinding);
    expect(result).toBe(
      ["const a = createHash('sha256');", 'const b = createHash("sha256");'].join("\n")
    );
  });

  it("returns null when no md5 found", () => {
    const input = "const hash = createHash('sha256');";
    const result = crypto002Fixer.apply!(input, stubFinding);
    expect(result).toBeNull();
  });

  it("is idempotent — second run on fixed output returns null", () => {
    const input = "const hash = createHash('md5');";
    const first = crypto002Fixer.apply!(input, stubFinding)!;
    const second = crypto002Fixer.apply!(first, stubFinding);
    expect(second).toBeNull();
  });
});
