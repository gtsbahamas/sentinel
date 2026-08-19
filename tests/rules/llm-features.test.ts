import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { cpSync, mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { resetRegistry, registerRules, runRules } from "../../src/layers/rules/index.js";
import { llmFeatureRules } from "../../src/layers/rules/domains/llm-features.js";
import { runRecon } from "../../src/layers/recon/index.js";
import type { Finding } from "../../src/model/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * The llm-features rules deliberately skip paths containing `/tests/` or
 * `/fixtures/` — real projects keep intentionally-bad code there. So the
 * fixtures are copied into a temp directory before scanning, which is also
 * closer to how a real repo looks.
 */
function stageFixture(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), "llm-fixture-"));
  cpSync(join(__dirname, "..", "fixtures", name), dir, { recursive: true });
  return dir;
}

async function scan(root: string): Promise<Finding[]> {
  resetRegistry();
  registerRules(llmFeatureRules);
  const model = await runRecon(root, ["node_modules"]);
  return runRules(model);
}

let vulnerable: Finding[];
let safe: Finding[];
let vulnerableRoot: string;
let safeRoot: string;

beforeAll(async () => {
  vulnerableRoot = stageFixture("vulnerable-ai-app");
  safeRoot = stageFixture("safe-ai-app");
  vulnerable = await scan(vulnerableRoot);
  safe = await scan(safeRoot);
});

afterAll(() => {
  rmSync(vulnerableRoot, { recursive: true, force: true });
  rmSync(safeRoot, { recursive: true, force: true });
});

function byRule(findings: Finding[], id: string): Finding[] {
  return findings.filter((f) => f.ruleId === id);
}

describe("llm-features rules", () => {
  it("registers at least four LLM-* rules", () => {
    expect(llmFeatureRules.length).toBeGreaterThanOrEqual(4);
    for (const rule of llmFeatureRules) {
      expect(rule.id).toMatch(/^LLM-\d{3}$/);
      expect(rule.domain).toBe("llm-features");
      expect(typeof rule.check).toBe("function");
    }
  });

  it("gives every rule an LLM-family CWE and OWASP LLM01 reference", () => {
    for (const rule of llmFeatureRules) {
      expect(rule.references.owasp).toBe("OWASP-LLM01:2025");
      expect(["CWE-1427", "CWE-1426"]).toContain(rule.references.cwe);
    }
  });

  it("writes impact in the ShipSafe coaching voice, not attacker recon language", () => {
    for (const rule of llmFeatureRules) {
      expect(rule.impact).toMatch(/^Your app\b/);
      expect(rule.impact).toMatch(/\bAn attacker\b/);
      // House style: no em dashes in user-facing finding prose.
      expect(rule.impact).not.toContain("\u2014");
      expect(rule.description).not.toContain("\u2014");
      expect(rule.impact.length).toBeGreaterThan(80);
    }
  });

  // -------------------------------------------------------------------------
  // Positive detection — the fixture has one unsanitized sink per rule.
  // -------------------------------------------------------------------------

  it("produces LLM-* findings on the vulnerable AI fixture", () => {
    expect(vulnerable.length).toBeGreaterThan(0);
    expect(vulnerable.every((f) => f.domain === "llm-features")).toBe(true);
  });

  it("flags user input spliced into a system prompt (LLM-001)", () => {
    const hits = byRule(vulnerable, "LLM-001");
    expect(hits.length).toBe(1);
    expect(hits[0].evidence[0].file).toMatch(/api\/chat\/route\.ts$/);
    expect(hits[0].severity).toBe("high");
    expect(hits[0].confidence).toBe("high");
    expect(hits[0].evidence[0].snippet).toContain("${message}");
  });

  it("flags fetched page content spliced into a prompt (LLM-002)", () => {
    const hits = byRule(vulnerable, "LLM-002");
    expect(hits.length).toBe(1);
    expect(hits[0].evidence[0].file).toMatch(/api\/summarize\/route\.ts$/);
    expect(hits[0].evidence[0].snippet).toContain("${pageText}");
  });

  it("flags model output rendered as HTML (LLM-003)", () => {
    const hits = byRule(vulnerable, "LLM-003");
    expect(hits.length).toBe(1);
    expect(hits[0].evidence[0].file).toMatch(/AnswerPanel\.tsx$/);
    expect(hits[0].evidence[0].snippet).toContain("dangerouslySetInnerHTML");
  });

  it("flags model output executed as SQL (LLM-004)", () => {
    const hits = byRule(vulnerable, "LLM-004");
    expect(hits.length).toBe(1);
    expect(hits[0].evidence[0].file).toMatch(/api\/report\/route\.ts$/);
    expect(hits[0].severity).toBe("critical");
    expect(hits[0].evidence[0].snippet).toContain("db.query(sql)");
  });

  it("flags unvalidated model-chosen tool arguments (LLM-005)", () => {
    const hits = byRule(vulnerable, "LLM-005");
    expect(hits.length).toBe(1);
    expect(hits[0].evidence[0].file).toMatch(/api\/agent\/route\.ts$/);
    expect(hits[0].severity).toBe("high");
    expect(hits[0].evidence[0].snippet).toContain("JSON.parse(call.function.arguments)");
  });

  // -------------------------------------------------------------------------
  // False-positive control — the safe fixture uses the correct shapes AND
  // contains a non-LLM file full of scary patterns. Zero findings expected.
  // -------------------------------------------------------------------------

  it("produces zero findings on the safe AI fixture", () => {
    expect(safe.map((f) => `${f.ruleId} ${f.evidence[0]?.file}`)).toEqual([]);
  });

  it("does not fire on files with no LLM in them", async () => {
    // The safe fixture's legacy-render.ts has innerHTML and template-literal
    // SQL. Neither is an llm-features concern without a model in the loop.
    expect(safe.filter((f) => /legacy-render/.test(f.evidence[0]?.file ?? ""))).toEqual([]);
  });
});
