import { describe, it, expect } from "vitest";
import { severityRank, isAtOrAbove, compareSeverity } from "../../src/model/severity.js";

describe("severity", () => {
  it("ranks critical highest and info lowest", () => {
    expect(severityRank("critical")).toBe(4);
    expect(severityRank("high")).toBe(3);
    expect(severityRank("medium")).toBe(2);
    expect(severityRank("low")).toBe(1);
    expect(severityRank("info")).toBe(0);
  });

  it("isAtOrAbove returns true when severity meets threshold", () => {
    expect(isAtOrAbove("critical", "high")).toBe(true);
    expect(isAtOrAbove("high", "high")).toBe(true);
    expect(isAtOrAbove("medium", "high")).toBe(false);
  });

  it("compareSeverity sorts critical first", () => {
    const sorted = ["low", "critical", "medium", "high"].sort(compareSeverity);
    expect(sorted).toEqual(["critical", "high", "medium", "low"]);
  });
});
