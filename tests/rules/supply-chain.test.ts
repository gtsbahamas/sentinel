import { describe, it, expect, beforeEach } from "vitest";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { supplyChainRules } from "../../src/layers/rules/domains/supply-chain.js";
import { runRecon } from "../../src/layers/recon/index.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { mkdtempSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { emptyModel, makeDep } from "./helpers.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(__dirname, "..", "fixtures", "vulnerable-nextjs");

/** Helper: get the rule object by ID. */
function getRule(id: string) {
  const rule = supplyChainRules.find((r) => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

describe("supply-chain rules", () => {
  // ---- Fixture-based tests (existing) ----

  it("flags flatmap-stream (SUPPLY-001)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "SUPPLY-001").length).toBeGreaterThanOrEqual(1);
  });

  it("flags missing lockfile (SUPPLY-002)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "SUPPLY-002").length).toBe(1);
  });

  it("flags postinstall lifecycle script (SUPPLY-003)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "SUPPLY-003").length).toBeGreaterThanOrEqual(1);
  });

  it("flags wildcard version (SUPPLY-004)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    expect(findings.filter((f) => f.ruleId === "SUPPLY-004").length).toBeGreaterThanOrEqual(1);
  });

  it("flags deprecated package (SUPPLY-010)", async () => {
    resetRegistry();
    registerRules(supplyChainRules);
    const model = await runRecon(fixturePath, ["node_modules"]);
    const findings = await runRules(model);
    const deprecated = findings.filter((f) => f.ruleId === "SUPPLY-010");
    expect(deprecated.length).toBeGreaterThanOrEqual(1);
    expect(deprecated.some((f) => /request/.test(f.title))).toBe(true);
  });

  // ---- Direct rule.check() tests for untested rules ----

  // SUPPLY-001 additional: test minimatch semver boundary after audit fix
  describe("SUPPLY-001 minimatch boundary", () => {
    const rule = getRule("SUPPLY-001");

    it("flags minimatch@3.0.4 as vulnerable", async () => {
      const model = emptyModel({ dependencies: [makeDep("minimatch", "3.0.4")] });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain("minimatch");
    });

    it("does NOT flag minimatch@3.0.5 (patched)", async () => {
      const model = emptyModel({ dependencies: [makeDep("minimatch", "3.0.5")] });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });

    it("does NOT flag minimatch@3.0.6 (patched)", async () => {
      const model = emptyModel({ dependencies: [makeDep("minimatch", "3.0.6")] });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });
  });

  // SUPPLY-005: Git or file: URL dependency
  describe("SUPPLY-005", () => {
    const rule = getRule("SUPPLY-005");

    it("flags a git+https dependency", async () => {
      const model = emptyModel({
        dependencies: [makeDep("my-lib", "git+https://github.com/user/repo.git#main")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("SUPPLY-005");
      expect(findings[0].title).toContain("git");
    });

    it("flags a file: dependency", async () => {
      const model = emptyModel({
        dependencies: [makeDep("local-pkg", "file:../local-pkg")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain("local path");
    });

    it("flags a git@ SSH dependency", async () => {
      const model = emptyModel({
        dependencies: [makeDep("ssh-lib", "git@github.com:user/repo.git")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
    });

    it("does NOT flag a normal semver version", async () => {
      const model = emptyModel({
        dependencies: [makeDep("lodash", "4.17.21")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });
  });

  // SUPPLY-006: Typosquat detection
  describe("SUPPLY-006", () => {
    const rule = getRule("SUPPLY-006");

    it("flags a known typosquat (loadash -> lodash)", async () => {
      const model = emptyModel({
        dependencies: [makeDep("loadash", "1.0.0")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("SUPPLY-006");
      expect(findings[0].title).toContain("loadash");
      expect(findings[0].title).toContain("lodash");
    });

    it("flags crossenv (typosquat of cross-env)", async () => {
      const model = emptyModel({
        dependencies: [makeDep("crossenv", "7.0.0")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain("crossenv");
    });

    it("does NOT flag the real package (lodash)", async () => {
      const model = emptyModel({
        dependencies: [makeDep("lodash", "4.17.21")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });

    it("does NOT flag the real cross-env package", async () => {
      const model = emptyModel({
        dependencies: [makeDep("cross-env", "7.0.3")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });
  });

  // SUPPLY-007: Dev tool in production dependencies
  describe("SUPPLY-007", () => {
    const rule = getRule("SUPPLY-007");

    it("flags jest in production dependencies", async () => {
      const model = emptyModel({
        dependencies: [makeDep("jest", "29.7.0", "production")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("SUPPLY-007");
      expect(findings[0].title).toContain("jest");
    });

    it("flags eslint in production dependencies", async () => {
      const model = emptyModel({
        dependencies: [makeDep("eslint", "8.50.0", "production")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
    });

    it("does NOT flag jest in devDependencies", async () => {
      const model = emptyModel({
        dependencies: [makeDep("jest", "29.7.0", "dev")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });

    it("does NOT flag a normal production dependency", async () => {
      const model = emptyModel({
        dependencies: [makeDep("express", "4.18.2", "production")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });
  });

  // SUPPLY-008: Severely outdated major version
  describe("SUPPLY-008", () => {
    const rule = getRule("SUPPLY-008");

    it("flags next@12 as below minimum (13)", async () => {
      const model = emptyModel({
        dependencies: [makeDep("next", "12.3.4")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("SUPPLY-008");
      expect(findings[0].title).toContain("v12");
    });

    it("flags react@17 as below minimum (18)", async () => {
      const model = emptyModel({
        dependencies: [makeDep("react", "17.0.2")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toContain("v17");
    });

    it("flags @supabase/supabase-js@1 as below minimum (2)", async () => {
      const model = emptyModel({
        dependencies: [makeDep("@supabase/supabase-js", "1.35.0")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
    });

    it("does NOT flag next@14 (at or above minimum)", async () => {
      const model = emptyModel({
        dependencies: [makeDep("next", "14.2.0")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });

    it("does NOT flag react@18", async () => {
      const model = emptyModel({
        dependencies: [makeDep("react", "18.2.0")],
      });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });
  });

  // SUPPLY-009: Duplicate package versions in lockfile
  describe("SUPPLY-009", () => {
    const rule = getRule("SUPPLY-009");

    it("flags a package with 3+ duplicate versions in lockfile", async () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "supply009-"));
      // Create a minimal package-lock.json v3 with 3 versions of the same package
      const lockfile = {
        name: "test-project",
        lockfileVersion: 3,
        packages: {
          "": { name: "test-project", version: "1.0.0" },
          "node_modules/debug": { version: "2.6.9" },
          "node_modules/foo/node_modules/debug": { version: "3.2.7" },
          "node_modules/bar/node_modules/debug": { version: "4.3.4" },
        },
      };
      writeFileSync(join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
      const model = emptyModel({ meta: { ...emptyModel().meta, path: tmpDir } });
      const findings = await rule.check(model);
      expect(findings.length).toBe(1);
      expect(findings[0].ruleId).toBe("SUPPLY-009");
      expect(findings[0].title).toContain("debug");
      expect(findings[0].title).toContain("3");
    });

    it("does NOT flag a package with only 2 versions (below threshold)", async () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "supply009-"));
      const lockfile = {
        name: "test-project",
        lockfileVersion: 3,
        packages: {
          "": { name: "test-project", version: "1.0.0" },
          "node_modules/debug": { version: "3.2.7" },
          "node_modules/foo/node_modules/debug": { version: "4.3.4" },
        },
      };
      writeFileSync(join(tmpDir, "package-lock.json"), JSON.stringify(lockfile));
      const model = emptyModel({ meta: { ...emptyModel().meta, path: tmpDir } });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });

    it("returns no findings when no lockfile exists", async () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "supply009-"));
      // No package-lock.json created
      const model = emptyModel({ meta: { ...emptyModel().meta, path: tmpDir } });
      const findings = await rule.check(model);
      expect(findings.length).toBe(0);
    });
  });
});
