import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  formatPatterns,
  patternsToConventions,
  mergeConventions,
} from "../../src/commands/patterns.js";
import type { InferredPattern } from "../../src/model/types.js";

function pattern(overrides: Partial<InferredPattern> = {}): InferredPattern {
  return {
    domain: "auth",
    pathGlob: "src/app/api/admin/**",
    dominantHelper: "requireStaffPermission",
    prevalence: 1.0,
    sampleSize: 17,
    evidenceFiles: [
      "src/app/api/admin/users/route.ts",
      "src/app/api/admin/disputes/[id]/route.ts",
      "src/app/api/admin/audit-log/route.ts",
    ],
    ...overrides,
  };
}

// Strip ANSI color codes so assertions stay readable. Chalk emits color in
// CI when forced, and we don't want every assertion to bake escape sequences.
function strip(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1B\[[0-9;]*m/g, "");
}

describe("formatPatterns (pretty-print)", () => {
  it("renders 2 patterns with helper, prevalence, and evidence files", () => {
    const patterns = [
      pattern(),
      pattern({
        pathGlob: "src/app/api/portal/**",
        dominantHelper: "requirePortalSession",
        prevalence: 0.75,
        sampleSize: 12,
        evidenceFiles: [
          "src/app/api/portal/account/route.ts",
          "src/app/api/portal/orders/route.ts",
          "src/app/api/portal/profile/route.ts",
        ],
      }),
    ];
    const out = strip(formatPatterns("/path/to/project", patterns));

    expect(out).toContain("Sentinel patterns inferred from /path/to/project");
    expect(out).toContain("src/app/api/admin/**");
    expect(out).toContain("requireStaffPermission()");
    expect(out).toContain("17 of 17 endpoints (100%)");
    expect(out).toContain("e.g. src/app/api/admin/users/route.ts");
    expect(out).toContain("src/app/api/admin/disputes/[id]/route.ts");

    expect(out).toContain("src/app/api/portal/**");
    expect(out).toContain("requirePortalSession()");
    // 0.75 * 12 = 9
    expect(out).toContain("9 of 12 endpoints (75%)");

    expect(out).toContain("2 patterns inferred");
    expect(out).toContain("sentinel patterns --init");
  });

  it("renders the empty-state message when no patterns are inferred", () => {
    const out = strip(formatPatterns("/path/to/tiny-project", []));

    expect(out).toContain("No auth patterns inferred from /path/to/tiny-project");
    expect(out).toContain("at least 5 endpoints");
    expect(out).toContain("60% convergence");
    expect(out).toContain('"conventions"');
    expect(out).toContain("requireStaffPermission");
    // Make sure we didn't accidentally print the "N patterns inferred" footer
    expect(out).not.toContain("patterns inferred. Run");
  });

  it("uses singular 'pattern' when exactly one is inferred", () => {
    const out = strip(formatPatterns("/proj", [pattern()]));
    expect(out).toContain("1 pattern inferred");
    expect(out).not.toContain("1 patterns inferred");
  });
});

describe("patternsToConventions", () => {
  it("converts inferred patterns to convention blocks", () => {
    const conventions = patternsToConventions([
      pattern(),
      pattern({
        pathGlob: "src/app/api/portal/**",
        dominantHelper: "requirePortalSession",
      }),
    ]);
    expect(conventions).toEqual([
      { match: "src/app/api/admin/**", require: "requireStaffPermission" },
      { match: "src/app/api/portal/**", require: "requirePortalSession" },
    ]);
  });
});

describe("mergeConventions", () => {
  it("adds conventions to a config that has none", () => {
    const merged = mergeConventions({ failOn: "high" }, [pattern()], false);
    expect(merged).toEqual({
      failOn: "high",
      conventions: [
        { match: "src/app/api/admin/**", require: "requireStaffPermission" },
      ],
    });
  });

  it("refuses to overwrite an existing non-empty conventions array without force", () => {
    const existing = {
      conventions: [{ match: "src/app/api/old/**", require: "oldHelper" }],
    };
    expect(() => mergeConventions(existing, [pattern()], false)).toThrow(
      /already contains a 'conventions' array/,
    );
  });

  it("overwrites existing conventions when force is true", () => {
    const existing = {
      conventions: [{ match: "src/app/api/old/**", require: "oldHelper" }],
    };
    const merged = mergeConventions(existing, [pattern()], true);
    expect(merged.conventions).toEqual([
      { match: "src/app/api/admin/**", require: "requireStaffPermission" },
    ]);
  });

  it("treats an empty existing conventions array as no conflict", () => {
    const merged = mergeConventions({ conventions: [] }, [pattern()], false);
    expect(merged.conventions).toEqual([
      { match: "src/app/api/admin/**", require: "requireStaffPermission" },
    ]);
  });
});

describe("--init filesystem behavior (via mergeConventions + write)", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "sentinel-patterns-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("writes a .sentinelrc.json with the right shape when none exists", () => {
    const merged = mergeConventions({}, [pattern()], false);
    const path = join(dir, ".sentinelrc.json");
    writeFileSync(path, JSON.stringify(merged, null, 2) + "\n", "utf-8");

    expect(existsSync(path)).toBe(true);
    const parsed = JSON.parse(readFileSync(path, "utf-8"));
    expect(parsed.conventions).toEqual([
      { match: "src/app/api/admin/**", require: "requireStaffPermission" },
    ]);
  });

  it("preserves unrelated config keys when merging", () => {
    const original = { failOn: "high", exclude: ["node_modules"] };
    const merged = mergeConventions(original, [pattern()], false);
    expect(merged.failOn).toBe("high");
    expect(merged.exclude).toEqual(["node_modules"]);
    expect(merged.conventions).toBeDefined();
  });
});
